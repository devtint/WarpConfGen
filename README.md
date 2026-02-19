# WarpConfGen

FastAPI web app to generate Cloudflare WARP WireGuard configs.

## Features

- Generate WireGuard key pair and registration payload
- Keep private key material out of UI output (no `wireguard://` URI display)
- Generate downloadable `.conf`
- Generate downloadable QR `.png`
- Save generation history in each user's browser local storage (history can re-download the generated `.conf` and view/download the QR)
- Send webhook notification when a key is generated (server tracks generation success/failure counts)
- Endpoint selection modes:
  - Auto (first reachable / fallback candidate)
  - Select from probed list
  - Custom IP
- Configurable endpoint port (default: `500`)
- Built-in IP probe table

## Tech Stack

- Python 3.12+
- FastAPI
- Uvicorn
- Requests
- PyNaCl
- qrcode + Pillow

## Local Run

```bash
pip install -r requirements.txt
cp .env.example .env  # Windows PowerShell: Copy-Item .env.example .env
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open: `http://127.0.0.1:8000`

### Environment

Use `.env` (auto-loaded) to configure runtime options:

```dotenv
WEBHOOK_URL=https://webhook.site/your-id
WEBHOOK_READ_URL=
WEBHOOK_CUTOFF_DATE=2026-02-25
STATS_FILE=warpgen_stats.json
```

- `WEBHOOK_URL` empty/unset = webhook notifications disabled
- `WEBHOOK_READ_URL` optional explicit JSON endpoint to read webhook requests
- `WEBHOOK_CUTOFF_DATE` counts webhook-read results only up to this date (inclusive)
- `STATS_FILE` controls where generation success/fail counters are stored

## Vercel Deploy

This repo is configured for Vercel serverless Python runtime.

### Included files

- `vercel.json`
- `api/index.py` (exports `app` from `main.py`)

### Deploy

```bash
npm i -g vercel
vercel login
vercel
vercel --prod
```

## Notes

- Webhook URL can be customized with `WEBHOOK_URL` environment variable (leave empty to disable). See `.env.example` for an example.
- Generation metrics shown in UI:
  - `Total Gen`
  - `Gen success` (webhook HTTP 2xx)
  - `Gen failed` (webhook non-2xx or request error)
- Local history is browser-based and supports re-download of `.conf` and view/download of QR.
- The app includes endpoint probing. In some serverless environments UDP probing may be restricted; auto mode falls back to first available candidate.
- This project is MIT licensed and intended for educational purposes.

## Project Structure

```text
api/
  index.py
main.py
requirements.txt
vercel.json
README.md
.env.example
```
