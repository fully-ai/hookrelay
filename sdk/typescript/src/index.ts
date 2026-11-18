import crypto from "node:crypto";

export interface HookRelayOptions {
  apiUrl: string;
  apiKey: string;
}

export function verifySignature(
  payload: string | Buffer,
  header: string,
  secret: string,
  toleranceSec = 300
): boolean {
  const pairs: Record<string, string[]> = {};
  for (const part of header.split(",")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    (pairs[k] ??= []).push(v);
  }
  const ts = Number(pairs.t?.[0] ?? NaN);
  if (!Number.isFinite(ts)) return false;
  if (toleranceSec > 0 && Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSec) {
    return false;
  }
  const raw = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  const signed = Buffer.concat([Buffer.from(`${ts}.`, "utf8"), raw]);
  const expected = crypto.createHmac("sha256", secret).update(signed).digest("hex");
  const candidates = [...(pairs.v1 ?? []), ...(pairs.v0 ?? [])];
  return candidates.some((cand) => {
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(cand, "utf8");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

export class HookRelayClient {
  private readonly apiUrl: string;
  private readonly apiKey: string;

  constructor(opts: HookRelayOptions) {
    this.apiUrl = opts.apiUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
  }

  async createEndpoint(url: string, eventPatterns: string[] = ["*"]) {
    const res = await fetch(`${this.apiUrl}/api/endpoints`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, event_patterns: eventPatterns }),
    });
    if (!res.ok) throw new Error(`HookRelay HTTP ${res.status}`);
    return res.json();
  }

  async publishEvent(eventType: string, payload: Record<string, unknown>, idempotencyKey?: string) {
    const res = await fetch(`${this.apiUrl}/api/events`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        event_type: eventType,
        payload,
        idempotency_key: idempotencyKey ?? null,
      }),
    });
    if (!res.ok) throw new Error(`HookRelay HTTP ${res.status}`);
    return res.json();
  }
}
