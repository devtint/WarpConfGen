# 🛡️ WarpGen

Modern FastAPI web app to generate Cloudflare WARP (WireGuard) VPN configurations — with a premium glassmorphism UI and Myanmar language support.

![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Deploy](https://img.shields.io/badge/Deploy-Vercel-black?logo=vercel)

---

## ✨ Features

- **Premium Glassmorphism UI** — Warm off-white palette, frosted glass cards, Outfit + DM Mono fonts, micro-animations
- **3 Endpoint Modes** — Default IPs, From List, Custom IP
- **Bilingual** — English + Myanmar (Burmese) language toggle
- **Config History** — Last 5 generated configs saved in localStorage for quick retrieval
- **QR Code Export** — Scan directly with WireGuard mobile app
- **Copy to Clipboard** — One-click config copy with toast notification
- **Download .conf** — Ready-to-import WireGuard configuration file
- **Port Selection** — Dropdown with common WARP ports (500, 2408, 1701, 4500)
- **Rate Limiting** — 15 requests per 60-second window per IP
- **V2BOX Subscription** — Permanent JIT (Just-In-Time) subscription link for V2BOX, Shadowrocket, and v2rayN with auto-refresh
- **V2BOX Double-Encode Fix** — Special URI encoding to survive V2BOX's double-decode pipeline
- **High Rate Limit** — Dedicated higher quota (100/min) for subscription syncs
- **Structured Logging** — JSON-structured logs via `structlog` (no more silent errors)
- **Async I/O** — Non-blocking Cloudflare API calls via `httpx`
- **Universal Config** — Generated WireGuard configs work with any WireGuard-supported app (v2rayNG, V2BOX, Amnezia VPN, NekoBox, and more)
- **Telegram Bot (Optional)** — Generate configs directly via Telegram with your own bot (Bilingual EN/MY)


---

## 🏗️ Architecture

```
WarpGen/
├── app/
│   ├── __init__.py              # App factory + structlog config
│   ├── config.py                # Pydantic Settings (typed, validated)
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── api.py               # POST /api/generate, GET /api/v2sub
│   │   ├── bot.py               # POST /api/bot (Telegram Webhook)
│   │   └── pages.py             # GET / (Jinja2 template)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── warp.py              # Cloudflare registration (async httpx)
│   │   ├── stats.py             # Local + Supabase stats tracking
│   │   └── subscription.py      # JIT v2box subscription management
│   └── middleware/
│       ├── __init__.py
│       └── rate_limit.py        # Path-specific sliding-window limiter
├── templates/
│   └── index.html               # Jinja2 template (HTML/CSS/JS)
├── api/
│   ├── __init__.py
│   └── index.py                 # Vercel serverless entry point
├── main.py                      # Local dev entry point
├── requirements.txt
├── vercel.json                  # Vercel deployment config
├── supabase_setup.sql           # Optional DB setup script
├── .env.example                 # Environment variable template
└── local_tools/                 # Directory for locally generated tools/scripts
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12+, FastAPI, Uvicorn |
| **HTTP Client** | httpx (async) |
| **Crypto** | PyNaCl (WireGuard key generation) |
| **Templates** | Jinja2 |
| **Config** | pydantic-settings |
| **Logging** | structlog |
| **UI** | Vanilla HTML/CSS/JS, Lucide Icons, Google Fonts |
| **Database** | Supabase (optional, for global stats) |
| **Deployment** | Vercel (serverless Python) |

---

## 🚀 Local Development

### Prerequisites

- Python 3.12+
- pip

### Setup

```bash
# 1. Create and activate a virtual environment (Recommended)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your optional configurations (Supabase, Telegram, etc.)

# 4. Run the dev server
python main.py
```

Open: **http://127.0.0.1:8000**

---

## ☁️ Vercel Deployment

### 1. Deploy

```bash
vercel --prod
```

### 2. Set Environment Variables

In **Vercel Dashboard → Project Settings → Environment Variables**, add the relevant variables you wish to use (all are optional depending on the features you want):

| Variable | Description |
|----------|-------------|
| `SUPABASE_URL` | Your Supabase project URL (for global stats and subscriptions) |
| `SUPABASE_KEY` | Your Supabase anon/public key |
| `TELEGRAM_BOT_TOKEN` | Your Telegram Bot Token from @BotFather |
| `APP_URL` | Your production Vercel URL (e.g. `https://warpgen.vercel.app`) - Needed for Telegram Bot Webhook |
| `ADMIN_SECRET` | A secret key to secure your `/api/bot/setup` endpoint |

---

## 🗄️ Supabase Setup (Optional)

To enable the global generation counter and database-backed V2BOX subscriptions:

1. Create a project on [Supabase](https://supabase.com)
2. Run the setup script in the **SQL Editor** (copy contents of `supabase_setup.sql` and execute).
3. Add your `SUPABASE_URL` and `SUPABASE_KEY` to `.env` (local) or Vercel env vars (production).

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the WarpGen web UI |
| `POST` | `/api/generate` | Generate a WARP config (form data: `mode`, `port`, etc) |
| `GET` | `/api/sub` | Subscription endpoint returning Base64 encoded `wireguard://` URI |
| `GET` | `/api/v2sub/{sub_id}` | **Dynamic Feed:** Generates & serves fresh Warp config for V2BOX |
| `POST` | `/api/v2sub/update` | Refresh or create a V2BOX subscription and save to Supabase |
| `POST` | `/api/bot` | Telegram Webhook handler |
| `GET` | `/api/bot/setup` | One-time Webhook registration (protect with `?key=ADMIN_SECRET`) |
| `GET` | `/api/health` | Server health check with template directory info |

### Example: Generate via API

```bash
curl -X POST http://127.0.0.1:8000/api/generate \
  -d "mode=auto&port=500"
```

---

## 🤖 Telegram Bot (Optional)

WarpGen includes a lightweight Telegram bot integration for on-the-go config generation. **This feature is completely optional.**

### Setup Instructions

1. **Get a Token:** Message [@BotFather](https://t.me/BotFather) to create a bot and get your token.
2. **Set Env Vars:** Add `TELEGRAM_BOT_TOKEN` and `APP_URL` to your Vercel project environment variables. We also recommend setting `ADMIN_SECRET` for security.
3. **Register Webhook:** After deployment, visit `https://your-domain.vercel.app/api/bot/setup?key=YOUR_ADMIN_SECRET` in your browser to link the webhook.
4. **Start Chatting:** Open your bot on Telegram and send `/start`.

---

## 📱 V2BOX Subscription

WarpGen provides a permanent subscription URL for V2BOX, Shadowrocket, and v2rayN clients.

> ⚠️ **iOS Notice:** V2BOX Subscription is currently not working on iOS. We are working on a fix and will update soon.

### How It Works

1. Visit the website and copy your **Subscription URL** from the V2BOX card
2. In V2BOX, go to **Subscription → Add** and paste the URL
3. Every time V2BOX syncs/updates, it generates a **brand new WARP identity** automatically

### Important Notes

| Topic | Details |
|-------|---------|
| **Auto-Update** | V2BOX auto-updates your config every time you open the app. Each update registers a fresh WARP identity with Cloudflare. |
| **Disable Auto-Update** | To keep the same config, go to V2BOX: **Settings → Subscription → Turn off "Auto Update"** |
| **50 GB Data** | This is Cloudflare's free WARP data quota per registration. It auto-refreshes every time V2BOX updates your subscription — effectively unlimited! |
| **Double-Encoding** | The subscription URI uses double-encoded query parameters (`%252B` instead of `%2B`) to survive V2BOX's double-decode pipeline. This is intentional. |

---

## 🔗 Config Compatibility

The generated WireGuard configuration (via **Copy Config** or **Download .conf**) is a standard WireGuard config and works with **any** WireGuard-supported app:

- **WireGuard** (Official) — Android, iOS, Windows, Mac, Linux
- **v2rayNG** — Android
- **V2BOX** — Android, iOS
- **Amnezia VPN** — Android, iOS, Windows, Mac, Linux
- **NekoBox** — Android
- And any other app that supports WireGuard protocol

---

## 🌐 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SUPABASE_URL` | *(empty)* | Optional: Supabase project URL |
| `SUPABASE_KEY` | *(empty)* | Optional: Supabase anon key |
| `STATS_FILE` | `warpgen_stats.json` | Optional: Local stats fallback file |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Optional: Token for Telegram Bot integration |
| `APP_URL` | *(empty)* | Optional: The base URL of your deployed app (required if using Telegram Bot) |
| `ADMIN_SECRET` | *(empty)* | Optional: Secret key used to secure `/api/bot/setup` endpoint |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Optional: Time window in seconds for the rate limiter |
| `RATE_LIMIT_MAX_REQUESTS` | `15` | Optional: Maximum requests allowed per IP within the time window |
| `PEER_PUBLIC_KEY` | `bmXOC...` | Optional: WireGuard Peer Public Key for Cloudflare endpoint |

---

## 📝 License

MIT Licensed. This project is provided for educational purposes.

---

<p align="center">
  Made with ☕ by <a href="https://t.me/BadCodeWriter">@BadCodeWriter</a> · <a href="https://t.me/h3lpw1thvpn">Telegram Group</a>
</p>
