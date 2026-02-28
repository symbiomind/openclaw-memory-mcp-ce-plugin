/**
 * enrichment.ts — L3 label enrichment cron for openclaw-memory-mcp-ce-plugin
 *
 * Runs as a background service inside the plugin's registerService.
 * No OpenClaw agent overhead — just the plugin talking directly to:
 *   1. memory-mcp-ce  (retrieve unprocessed memories, replace_labels)
 *   2. Any OpenAI-compatible LLM endpoint (Ollama, OpenRouter, etc.)
 *
 * Flow:
 *   tick() fires on adaptive interval
 *   → fetch 1 memory with label = nonce (unprocessed)
 *   → send to tiny LLM, ask for 4-6 labels
 *   → validate output (retry once on bad format)
 *   → replace_labels: nonce → real semantic labels
 *   → reschedule based on remaining backlog count
 *
 * Mutex: enrichmentRunning flag prevents cascade stacking when the LLM
 * is slow. If a tick fires while the previous is still running, it skips.
 */

// ============================================================================
// Config
// ============================================================================

export interface EnrichmentConfig {
  /** Base URL of OpenAI-compatible LLM endpoint (e.g. http://localhost:11434) */
  enrichmentEndpoint: string;
  /** Model name (e.g. ministral-3:3b) */
  enrichmentModel: string;
  /** Bearer token for LLM endpoint (optional) */
  enrichmentApiKey?: string;
  /** Nonce label marking unprocessed memories (default: "52868312778495") */
  enrichmentNonce?: string;
  /** Max LLM request timeout in ms (default: 120000) */
  enrichmentTimeoutMs?: number;
  /** How many memories to process per tick (default: 1) */
  enrichmentBatchSize?: number;
}

const ENRICHMENT_DEFAULTS = {
  enrichmentNonce: "52868312778495",
  enrichmentTimeoutMs: 120_000,
  enrichmentBatchSize: 1,
};

// Adaptive interval thresholds
const INTERVAL_HIGH_MS   = 60_000;   //  1 min  — backlog > 100
const INTERVAL_MEDIUM_MS = 300_000;  //  5 min  — backlog 10–100
const INTERVAL_LOW_MS    = 900_000;  // 15 min  — backlog < 10
const INTERVAL_IDLE_MS   = 900_000;  // 15 min  — nothing to do

// ============================================================================
// Tiny LLM client (OpenAI-compat)
// ============================================================================

const SYSTEM_PROMPT =
  "You are a memory categorization system. Your job is to assign reusable topic category labels to conversation excerpts." +
  "\n" +
  "" +
  "\n" +
  "Output ONLY a comma-separated list of 4-6 labels. Rules:" +
  "\n" +
  "- lowercase, hyphenated, no spaces" +
  "\n" +
  "- REUSABLE: labels must be broad enough to apply to many different conversations" +
  "\n" +
  "- CATEGORICAL: use topic categories, not descriptions of specific events" +
  "\n" +
  "- no explanation, no newlines, no punctuation except commas" +
  "\n" +
  "" +
  "\n" +
  "Good examples: plugin-dev,memory-system,configuration,bug-fix,session-management,api-integration" +
  "\n" +
  "Bad examples: hype-induced-reset,mistress-priority-delay,test-secret-filter-canary (too specific/unique)";

async function callLlm(
  endpoint: string,
  model: string,
  content: string,
  apiKey: string | undefined,
  timeoutMs: number,
): Promise<string> {
  const url = `${endpoint.replace(/\/$/, "")}/v1/chat/completions`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        model,
        stream: false,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user",   content: `Label this conversation:\n\n${content}` },
        ],
      }),
    });

    if (!resp.ok) throw new Error(`LLM HTTP ${resp.status}`);

    const json = await resp.json() as {
      choices?: Array<{ message: { content: string } }>;
      message?: { content: string };
    };

    return (
      json.choices?.[0]?.message?.content ??
      json.message?.content ??
      ""
    ).trim();
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// Label validation + sanitisation
// ============================================================================

/**
 * Parse and validate raw LLM output into a clean comma-separated label string.
 * Returns null if the output doesn't meet quality bar (triggers retry).
 */
function parseLabels(raw: string): string | null {
  // Split on commas first, then clean each token individually
  // (avoids "user-frustration, mitigation" → "user-frustrationmitigation")
  const tokens = raw
    .split(",")
    .map(t => t.replace(/[\s!.]/g, "").toLowerCase())
    .filter(t => /^[a-z][a-z0-9-]+$/.test(t));

  if (tokens.length < 4 || tokens.length > 6) return null;

  return tokens.join(",");
}

// ============================================================================
// EnrichmentCron
// ============================================================================

interface McpClient {
  retrieveMemoriesStructured(
    query?: string,
    labels?: string,
    source?: string,
    numResults?: number,
  ): Promise<Array<{ id: number; content: string }>>;
  callTool(name: string, args: Record<string, unknown>): Promise<unknown>;
}

async function getUnprocessedCount(mcp: McpClient, nonce: string): Promise<number> {
  try {
    const result = await mcp.callTool("memory_stats", { labels: nonce }) as {
      content: Array<{ text: string }>;
    };
    const text = result.content.map((c) => c.text).join("");
    const parsed = JSON.parse(text) as { matching?: number };
    return parsed.matching ?? 0;
  } catch {
    return 0;
  }
}

interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
}

export class EnrichmentCron {
  private running = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private nonce: string;
  private timeoutMs: number;
  private batchSize: number;

  constructor(
    private readonly cfg: EnrichmentConfig,
    private readonly mcp: McpClient,
    private readonly logger: Logger,
  ) {
    this.nonce      = cfg.enrichmentNonce      ?? ENRICHMENT_DEFAULTS.enrichmentNonce;
    this.timeoutMs  = cfg.enrichmentTimeoutMs  ?? ENRICHMENT_DEFAULTS.enrichmentTimeoutMs;
    this.batchSize  = cfg.enrichmentBatchSize  ?? ENRICHMENT_DEFAULTS.enrichmentBatchSize;
  }

  start(): void {
    this.logger.info(
      `memory-mcp-ce enrichment: starting cron ` +
      `(model: ${this.cfg.enrichmentModel}, endpoint: ${this.cfg.enrichmentEndpoint})`,
    );
    this.schedule(60_000); // 60s warmup after gateway start, then adaptive
  }

  stop(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.logger.info("memory-mcp-ce enrichment: cron stopped");
  }

  private schedule(intervalMs: number): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.tick(), intervalMs);
  }

  private async tick(): Promise<void> {
    // Mutex — skip tick if previous is still running
    if (this.running) {
      this.logger.info("memory-mcp-ce enrichment: previous tick still running, skipping");
      this.schedule(INTERVAL_MEDIUM_MS);
      return;
    }

    this.running = true;
    let processed = 0;
    let remaining = 0;

    try {
      // Fetch unprocessed memories (by nonce label)
      const batch = await this.mcp.retrieveMemoriesStructured(
        undefined,
        this.nonce,
        undefined,
        this.batchSize,
      );

      if (batch.length === 0) {
        this.logger.info("memory-mcp-ce enrichment: no unprocessed memories — idling");
        this.schedule(INTERVAL_IDLE_MS);
        return;
      }

      for (const mem of batch) {
        const labels = await this.enrichOne(mem.id, mem.content);
        if (labels) {
          processed++;
          this.logger.info(
            `memory-mcp-ce enrichment: #${mem.id} → ${labels}`,
          );
        } else {
          this.logger.warn(
            `memory-mcp-ce enrichment: #${mem.id} — could not generate labels, skipping`,
          );
        }
      }

      // Check remaining backlog via memory_stats for accurate adaptive interval
      remaining = await getUnprocessedCount(this.mcp, this.nonce);

    } catch (err) {
      this.logger.warn(`memory-mcp-ce enrichment: tick error — ${String(err)}`);
    } finally {
      this.running = false;
    }

    if (processed > 0) {
      this.logger.info(
        `memory-mcp-ce enrichment: processed ${processed}, ` +
        `scheduling next tick`,
      );
    }

    // Adaptive interval based on real remaining backlog count
    const nextInterval =
      remaining > 100 ? INTERVAL_HIGH_MS   :
      remaining > 10  ? INTERVAL_MEDIUM_MS :
      remaining > 0   ? INTERVAL_LOW_MS    :
                        INTERVAL_IDLE_MS;

    this.schedule(nextInterval);
  }

  private async enrichOne(memId: number, content: string): Promise<string | null> {
    // Try up to 2 times
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const raw = await callLlm(
          this.cfg.enrichmentEndpoint,
          this.cfg.enrichmentModel,
          content,
          this.cfg.enrichmentApiKey,
          this.timeoutMs,
        );

        const labels = parseLabels(raw);
        if (labels) {
          // Replace nonce with real labels
          await this.mcp.callTool("replace_labels", {
            memory_id: memId,
            target: this.nonce,
            new: labels,
          });
          return labels;
        }

        this.logger.warn(
          `memory-mcp-ce enrichment: #${memId} attempt ${attempt} — bad output: "${raw.slice(0, 80)}"`,
        );
      } catch (err) {
        this.logger.warn(
          `memory-mcp-ce enrichment: #${memId} attempt ${attempt} — error: ${String(err)}`,
        );
      }
    }

    return null;
  }
}
