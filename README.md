# Signed Event Enrichment Demo

An edge Worker that accepts a signed synthetic security event, adds fixture network context, and returns a delivery preview. It demonstrates bounded request reading, timestamped HMAC verification, fail-closed configuration, and clear separation between event processing and notification delivery.

## Run

Run `node --test` with Node.js 18 or newer. For local Worker development, install Wrangler separately and run `wrangler dev`. Set a local `INGEST_SECRET` of at least 16 characters before calling `POST /preview`; keep it in local secret storage, never in the repository.

Sign the exact UTF-8 JSON body using HMAC-SHA256 with the secret. The signed message is `<unix-seconds>.<raw-body>`. Send the lowercase hex signature in `x-demo-signature` and the timestamp in `x-demo-timestamp`. The timestamp must be within five minutes. A sample body is `{"ip":"192.0.2.10","type":"blocked_login"}`.

## Safety boundary

All context comes from documentation-address fixtures. The Worker has no outgoing network calls and does not send notifications. The response explicitly says `delivered: false`. Replays inside the five-minute window only repeat a side-effect-free preview; any real delivery integration needs persistent replay protection, rate limits, and an independent security review. The default public Worker subdomain is disabled.
