const MAX_BODY_BYTES = 4096;
const MAX_AGE_SECONDS = 300;
const FIXTURES = Object.freeze({
  "192.0.2.10": { network: "Documentation network A", region: "Example region" },
  "2001:db8::10": { network: "Documentation IPv6 network", region: "Example region" }
});

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

function safeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function fromHex(value) {
  if (!/^[0-9a-f]{64}$/i.test(value || "")) return null;
  return Uint8Array.from(value.match(/.{2}/g), part => parseInt(part, 16));
}

export async function signBody(secret, timestamp, rawBody) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${rawBody}`));
  return new Uint8Array(signature);
}

async function readSmallText(request) {
  const reader = request.body?.getReader();
  if (!reader) return { error: "body_required", status: 400 };
  const parts = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        return { error: "body_too_large", status: 413 };
      }
      parts.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  try { return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) }; }
  catch { return { error: "invalid_encoding", status: 400 }; }
}

export function isValidIp(value) {
  if (typeof value !== "string" || value.length > 45 || value !== value.trim()) return false;
  if (value.includes(":")) {
    if (!/^[0-9a-fA-F:]+$/.test(value) || value.includes(":::")) return false;
    const parts = value.split("::");
    if (parts.length > 2) return false;
    const groups = parts.flatMap(part => part ? part.split(":") : []);
    if (groups.some(group => !/^[0-9a-fA-F]{1,4}$/.test(group))) return false;
    return parts.length === 2 ? groups.length < 8 : groups.length === 8;
  }
  const parts = value.split(".");
  return parts.length === 4 && parts.every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (request.method === "GET" && path === "/health") return json({ ok: true });
    if (path !== "/preview") return json({ error: "not_found" }, 404);
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
    if (typeof env?.INGEST_SECRET !== "string" || env.INGEST_SECRET.length < 16) return json({ error: "unavailable" }, 503);
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ error: "content_type_required" }, 415);

    const timestamp = request.headers.get("x-demo-timestamp");
    const signature = fromHex(request.headers.get("x-demo-signature"));
    const timestampNumber = Number(timestamp);
    if (!/^\d{10}$/.test(timestamp || "") || !signature || Math.abs(Date.now() / 1000 - timestampNumber) > MAX_AGE_SECONDS) {
      return json({ error: "unauthorized" }, 401);
    }

    const body = await readSmallText(request);
    if (body.error) return json({ error: body.error }, body.status);
    const expected = await signBody(env.INGEST_SECRET, timestamp, body.text);
    if (!safeEqual(signature, expected)) return json({ error: "unauthorized" }, 401);

    let event;
    try { event = JSON.parse(body.text); } catch { return json({ error: "invalid_json" }, 400); }
    if (!event || typeof event !== "object" || Array.isArray(event) || !isValidIp(event.ip)) return json({ error: "valid_ip_required" }, 400);
    if (!/^(blocked_login|unusual_login|sample_event)$/.test(event.type || "")) return json({ error: "invalid_event_type" }, 400);

    return json({
      accepted: true,
      delivery_preview: {
        title: "Synthetic security event",
        severity: event.type === "blocked_login" ? "high" : event.type === "unusual_login" ? "medium" : "info",
        event_type: event.type,
        address: event.ip,
        context: FIXTURES[event.ip] || null
      },
      delivered: false
    });
  }
};
