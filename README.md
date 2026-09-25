# APJ Threat Intelligence — standalone Cloudflare Worker app

Open-source threat intel dashboard (India P1 → APJ → Global): live feed, ransomware-leak tracker, MITRE-mapped actor profiles, INFOCON-driven severity banner, and a DarkGrid-style global attack globe.

Architecture:

- **`src/worker.js`** — Cloudflare Worker. A cron trigger runs every 30 minutes, fetches 9 RSS sources + ransomware.live, tags/dedupes/merges everything, and writes one JSON blob to Workers KV. `GET /api/data` serves that blob (cached, no live fetching on the request path — fast and can't fail from CORS/timeouts). `POST /api/refresh` (optional key-gated) triggers an on-demand collection.
- **`public/`** — static frontend (`index.html`, `styles.css`, `app.js`). Pure client-side rendering against `/api/data`. No build step, no framework, no API keys required to run.

This is meant to be opened in **Claude Code** on your machine and deployed with **Wrangler**, since deployment needs your Cloudflare login and account — that can't be done from this chat session.

## Prerequisites

- A Cloudflare account (free tier is enough)
- Node.js 18+
- `npm install -g wrangler` (or use `npx wrangler` throughout instead of installing globally)

## Setup

```bash
cd apj-threat-intel-app
npm install
wrangler login
```

Create the KV namespace the Worker uses to persist collected data:

```bash
wrangler kv namespace create THREAT_DATA
```

Copy the `id` it prints into `wrangler.toml`, replacing `REPLACE_WITH_YOUR_KV_NAMESPACE_ID`:

```toml
[[kv_namespaces]]
binding = "THREAT_DATA"
id = "paste-the-id-here"
```

## Optional configuration

Optional — the app works fully without it (unauthenticated manual refresh).

```bash
# require a header on POST /api/refresh so randoms can't force-trigger collection
wrangler secret put REFRESH_KEY
```

For local dev, copy `.dev.vars.example` to `.dev.vars` and fill in the same values.

## Run locally

```bash
wrangler dev
```

Open the printed `localhost` URL. The dashboard will show "no data yet" until the first collection runs — trigger one manually:

```bash
curl -X POST http://localhost:8787/api/refresh
```

(add `-H "x-refresh-key: <value>"` if you set `REFRESH_KEY`)

## Deploy

```bash
wrangler deploy
```

Wrangler prints your live `*.workers.dev` URL. The cron trigger (every 30 min, see `[triggers]` in `wrangler.toml`) starts collecting automatically — no manual step needed after the first deploy. If you want data immediately instead of waiting for the first cron tick:

```bash
curl -X POST https://<your-worker>.workers.dev/api/refresh
```

## Customizing

- **Sources**: edit the `SOURCES` array in `src/worker.js`.
- **Cron cadence**: edit `crons` in `wrangler.toml` (cron syntax, UTC).
- **Curated actor profiles**: edit `ACTORS` / `GLOBAL_ACTORS` in `public/app.js` — these are hand-maintained, not auto-collected (attribution confidence language should stay intact if you add entries).
- **Custom domain**: add a `routes` entry in `wrangler.toml` or attach a domain in the Cloudflare dashboard under Workers & Pages.

## Notes

- Ransomware entries are leak-site claims scraped from ransomware.live, not confirmed breaches — the UI labels them as such throughout.
- The INFOCON banner is parsed live from SANS Internet Storm Center's channel title — it's a real, sourced indicator, not a fabricated score.
- KV storage keeps a rolling 365-day window capped at 500 items / 400 victims, so the free KV tier's storage limits are never a concern.
