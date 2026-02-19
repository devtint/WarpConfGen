# WarpConfGen

FastAPI web app to generate Cloudflare WARP WireGuard configs.

## Features

- Generate WireGuard key pair and registration payload
- Build `wireguard://` URI
- Generate downloadable `.conf`
- Generate downloadable QR `.png`
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
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open: `http://127.0.0.1:8000`

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
```
