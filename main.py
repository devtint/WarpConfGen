import base64
from collections import defaultdict, deque
from datetime import date, datetime, timezone
import html
import io
import ipaddress
import json
import os
import re
import socket
from threading import Lock
import time
import urllib.parse

import qrcode
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from nacl.public import PrivateKey


KNOWN_WARP_IPS = [
    "162.159.192.1",
    "162.159.192.2",
    "162.159.192.3",
    "162.159.193.1",
    "162.159.193.2",
    "162.159.193.3",
    "188.114.96.1",
    "188.114.97.1",
]
PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
load_dotenv()
# WEBHOOK_URL must be provided via environment variable. Leave empty to disable notifications.
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
WEBHOOK_READ_URL = os.getenv("WEBHOOK_READ_URL", "")
WEBHOOK_CUTOFF_DATE = os.getenv("WEBHOOK_CUTOFF_DATE", "2026-02-25")
STATS_FILE = os.getenv("STATS_FILE", "warpgen_stats.json")


app = FastAPI(title="WARP Generator")


RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_GENERAL = 120
RATE_LIMIT_GENERATE = 20
_rate_limit_lock = Lock()
_rate_limit_buckets = defaultdict(deque)
_stats_lock = Lock()


def _load_stats():
    defaults = {
        "total_generations": 0,
        "webhook_success": 0,
        "webhook_failed": 0,
        "webhook_skipped": 0,
        "last_webhook_status_code": None,
        "webhook_received_total": 0,
        "webhook_received_upto_cutoff": 0,
        "webhook_last_sync_at": None,
        "webhook_tracking_state": "unknown",
        "webhook_sync_error": "",
    }
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return {
                "total_generations": int(data.get("total_generations", 0)),
                "webhook_success": int(data.get("webhook_success", 0)),
                "webhook_failed": int(data.get("webhook_failed", 0)),
                "webhook_skipped": int(data.get("webhook_skipped", 0)),
                "last_webhook_status_code": data.get("last_webhook_status_code"),
                "webhook_received_total": int(data.get("webhook_received_total", 0)),
                "webhook_received_upto_cutoff": int(data.get("webhook_received_upto_cutoff", 0)),
                "webhook_last_sync_at": data.get("webhook_last_sync_at"),
                "webhook_tracking_state": data.get("webhook_tracking_state", "unknown"),
                "webhook_sync_error": data.get("webhook_sync_error", ""),
            }
    except Exception:
        return defaults


def _save_stats(stats):
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as file:
            json.dump(stats, file)
    except Exception:
        pass


_stats = _load_stats()


def record_generation_stats(webhook_result):
    with _stats_lock:
        _stats["total_generations"] += 1
        status = webhook_result.get("status")
        _stats["last_webhook_status_code"] = webhook_result.get("status_code")

        if status == "success":
            _stats["webhook_success"] += 1
        elif status == "failed":
            _stats["webhook_failed"] += 1
        else:
            _stats["webhook_skipped"] = int(_stats.get("webhook_skipped", 0)) + 1
        _save_stats(_stats)


def get_generation_stats():
    with _stats_lock:
        return dict(_stats)


def _parse_cutoff_date():
    try:
        return datetime.strptime(WEBHOOK_CUTOFF_DATE, "%Y-%m-%d").date()
    except ValueError:
        return date(2026, 2, 25)


def _after_cutoff_today():
    return datetime.now(timezone.utc).date() > _parse_cutoff_date()


def _parse_iso_dt(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _extract_webhook_site_token(url):
    match = re.search(r"webhook\.site/([0-9a-fA-F-]{36})", url)
    if not match:
        return ""
    return match.group(1)


def sync_stats_from_webhook():
    now_iso = datetime.now(timezone.utc).isoformat()
    cutoff = _parse_cutoff_date()

    if not WEBHOOK_URL:
        with _stats_lock:
            _stats["webhook_tracking_state"] = "disabled"
            _stats["webhook_sync_error"] = "WEBHOOK_URL is empty"
            _stats["webhook_last_sync_at"] = now_iso
            _save_stats(_stats)
        return

    if _after_cutoff_today():
        with _stats_lock:
            _stats["webhook_tracking_state"] = "expired"
            _stats["webhook_sync_error"] = f"Tracking ended after {cutoff.isoformat()}"
            _stats["webhook_last_sync_at"] = now_iso
            _save_stats(_stats)
        return

    read_urls = []
    if WEBHOOK_READ_URL:
        read_urls.append(WEBHOOK_READ_URL)
    else:
        token = _extract_webhook_site_token(WEBHOOK_URL)
        if token:
            read_urls.extend(
                [
                    f"https://webhook.site/token/{token}/requests?sorting=newest",
                    f"https://webhook.site/token/{token}/requests",
                ]
            )

    if not read_urls:
        with _stats_lock:
            _stats["webhook_tracking_state"] = "error"
            _stats["webhook_sync_error"] = "Unable to derive WEBHOOK_READ_URL"
            _stats["webhook_last_sync_at"] = now_iso
            _save_stats(_stats)
        return

    requests_list = None
    last_error = ""

    for read_url in read_urls:
        try:
            response = requests.get(read_url, headers={"accept": "application/json"}, timeout=10)
            if response.status_code >= 400:
                last_error = f"HTTP {response.status_code}"
                continue

            payload = response.json()
            if isinstance(payload, dict):
                if isinstance(payload.get("data"), list):
                    requests_list = payload["data"]
                elif isinstance(payload.get("requests"), list):
                    requests_list = payload["requests"]
            elif isinstance(payload, list):
                requests_list = payload

            if requests_list is not None:
                break

            last_error = "Unexpected webhook response format"
        except Exception:
            last_error = "Webhook read connection error"

    if requests_list is None:
        with _stats_lock:
            _stats["webhook_tracking_state"] = "error"
            _stats["webhook_sync_error"] = last_error or "Webhook read failed"
            _stats["webhook_last_sync_at"] = now_iso
            _save_stats(_stats)
        return

    received_total = len(requests_list)
    received_upto_cutoff = 0

    for item in requests_list:
        if not isinstance(item, dict):
            continue
        created_value = item.get("created_at") or item.get("createdAt") or item.get("created")
        created_dt = _parse_iso_dt(created_value)
        if created_dt and created_dt.date() <= cutoff:
            received_upto_cutoff += 1

    with _stats_lock:
        _stats["webhook_received_total"] = received_total
        _stats["webhook_received_upto_cutoff"] = received_upto_cutoff
        _stats["webhook_tracking_state"] = "active"
        _stats["webhook_sync_error"] = ""
        _stats["webhook_last_sync_at"] = now_iso
        _save_stats(_stats)


def get_client_ip(request: Request):
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    client_ip = get_client_ip(request)
    now = time.time()

    is_generate = path == "/generate"
    limit = RATE_LIMIT_GENERATE if is_generate else RATE_LIMIT_GENERAL
    bucket_key = f"{client_ip}:{'generate' if is_generate else 'general'}"

    with _rate_limit_lock:
        bucket = _rate_limit_buckets[bucket_key]
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            return PlainTextResponse(
                f"Rate limit exceeded. Try again in {RATE_LIMIT_WINDOW_SECONDS} seconds.",
                status_code=429,
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        bucket.append(now)
        remaining = max(0, limit - len(bucket))

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Window"] = str(RATE_LIMIT_WINDOW_SECONDS)
    return response


def validate_ip(ip_text):
    ipaddress.ip_address(ip_text)
    return ip_text


def fetch_dns_candidate_ips():
    candidates = []
    try:
        response = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": "engage.cloudflareclient.com", "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=10,
        )
        data = response.json()
        for answer in data.get("Answer", []):
            ip = answer.get("data", "")
            try:
                ipaddress.ip_address(ip)
                candidates.append(ip)
            except ValueError:
                continue
    except Exception:
        pass
    return candidates


def probe_udp_endpoint(ip, port, timeout_sec):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout_sec)
            sock.connect((ip, port))
            sock.send(b"\x00")
        return True
    except OSError:
        return False


def collect_candidate_results(port, timeout_sec):
    candidates = []
    seen = set()
    for ip in KNOWN_WARP_IPS + fetch_dns_candidate_ips():
        if ip not in seen:
            candidates.append(ip)
            seen.add(ip)

    results = []
    for ip in candidates:
        ok = probe_udp_endpoint(ip, port, timeout_sec)
        results.append({"ip": ip, "ok": ok})
    return results


def build_wireguard_conf(private_key_b64, ipv4, ipv6, endpoint):
    address_value = ipv4 if not ipv6 else f"{ipv4}, {ipv6}"
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key_b64}\n"
        f"Address = {address_value}\n"
        "DNS = 1.1.1.1, 1.0.0.1\n\n"
        "[Peer]\n"
        f"PublicKey = {PEER_PUBLIC_KEY}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {endpoint}\n"
        "PersistentKeepalive = 25\n"
    )


def build_qr_base64(content):
    qr_image = qrcode.make(content)
    buffer = io.BytesIO()
    qr_image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def generate_warp_payload(endpoint_ip, endpoint_port):
    priv = PrivateKey.generate()
    pub = priv.public_key
    private_key_b64 = base64.b64encode(bytes(priv)).decode("utf-8")
    public_key_b64 = base64.b64encode(bytes(pub)).decode("utf-8")

    url = "https://api.cloudflareclient.com/v0a1925/reg"
    payload = {
        "key": public_key_b64,
        "warp_enabled": True,
        "tos": "2024-01-01T00:00:00.000Z",
        "type": "Android",
        "locale": "en_US",
    }
    headers = {"User-Agent": "okhttp/3.12.1", "Content-Type": "application/json"}

    response = requests.post(url, json=payload, headers=headers, timeout=15)
    response.raise_for_status()
    data = response.json()

    config = data.get("config", {})
    addr = config.get("interface", {}).get("addresses", {})
    reserved = config.get("client_cfg", {}).get("reserved", [0, 0, 0])

    ipv4 = addr.get("v4", "172.16.0.2/32")
    ipv6 = addr.get("v6", "")

    if not ipv4.endswith("/32"):
        ipv4 += "/32"
    if ipv6 and not ipv6.endswith("/128"):
        ipv6 += "/128"

    endpoint = f"{endpoint_ip}:{endpoint_port}"

    timestamp = int(time.time() * 1000)

    conf_content = build_wireguard_conf(private_key_b64=private_key_b64, ipv4=ipv4, ipv6=ipv6, endpoint=endpoint)
    qr_b64 = build_qr_base64(conf_content)

    return {
        "timestamp": timestamp,
        "conf_content": conf_content,
        "conf_filename": f"warp-{timestamp}.conf",
        "qr_filename": f"warp-{timestamp}.png",
        "qr_b64": qr_b64,
        "endpoint": endpoint,
    }


def send_generation_webhook(client_ip, mode, endpoint, port):
    if not WEBHOOK_URL:
        return {"status": "skipped", "status_code": None}

    if _after_cutoff_today():
        return {"status": "expired", "status_code": None}

    payload = {
        "event": "warp_key_generated",
        "timestamp": int(time.time()),
        "client_ip": client_ip,
        "mode": mode,
        "endpoint": endpoint,
        "port": port,
    }

    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=8)
        if 200 <= response.status_code < 300:
            return {"status": "success", "status_code": response.status_code}
        return {"status": "failed", "status_code": response.status_code}
    except Exception:
        return {"status": "failed", "status_code": None}


def render_page(candidate_results, output=None, error_text="", mode="auto", selected_ip="", custom_ip="", port=500, probe_timeout=1.0, stats=None, webhook_status=None):
    rows = ""
    options = ""
    for item in candidate_results:
        status = "OK" if item["ok"] else "FAIL"
        status_color = "#065f46" if item["ok"] else "#991b1b"
        status_bg = "#d1fae5" if item["ok"] else "#fee2e2"
        ip = html.escape(item["ip"])
        rows += f"<tr><td>{ip}</td><td><span style='padding:4px 10px;border-radius:999px;background:{status_bg};color:{status_color};font-weight:600'>{status}</span></td></tr>"
        options += f"<option value='{ip}' {'selected' if selected_ip == item['ip'] else ''}>{ip} [{status}]</option>"

    error_html = ""
    if error_text:
        error_html = f"<div style='margin-bottom:16px;padding:12px;border-radius:12px;background:#fee2e2;color:#991b1b'>{html.escape(error_text)}</div>"

    stats = stats or {
        "total_generations": 0,
        "webhook_success": 0,
        "webhook_failed": 0,
        "webhook_skipped": 0,
        "last_webhook_status_code": None,
        "webhook_received_total": 0,
        "webhook_received_upto_cutoff": 0,
        "webhook_last_sync_at": None,
        "webhook_tracking_state": "unknown",
        "webhook_sync_error": "",
    }
    webhook_status_html = ""
    if webhook_status == "success":
        webhook_status_html = "<span style='padding:4px 10px;border-radius:999px;background:#d1fae5;color:#065f46;font-weight:600'>Gen success</span>"
    elif webhook_status == "failed":
        webhook_status_html = ""
    elif webhook_status == "skipped":
        webhook_status_html = "<span style='padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:600'>Webhook disabled</span>"
    elif webhook_status == "expired":
        webhook_status_html = f"<span style='padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:600'>Tracking ended ({WEBHOOK_CUTOFF_DATE})</span>"

    tracking_state = stats.get("webhook_tracking_state", "unknown")
    tracking_status_html = ""
    if tracking_state == "active":
        tracking_status_html = "<span style='padding:4px 10px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-weight:600'>Webhook read active</span>"
    elif tracking_state == "error":
        tracking_status_html = "<span style='padding:4px 10px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:600'>Webhook read error</span>"
    elif tracking_state == "expired":
        tracking_status_html = f"<span style='padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:600'>Read expired ({WEBHOOK_CUTOFF_DATE})</span>"
    elif tracking_state == "disabled":
        tracking_status_html = "<span style='padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:600'>Webhook read disabled</span>"

    sync_error = html.escape(stats.get("webhook_sync_error", ""))
    sync_error_html = ""
    if sync_error:
        sync_error_html = f"<div style='margin-top:8px;color:#991b1b;font-size:13px'><strong>Read status:</strong> {sync_error}</div>"

    total_gen_display = int(stats.get("webhook_success", 0)) + int(stats.get("webhook_failed", 0))

    stats_html = f"""
    <section style="margin-top:16px;padding:14px;border-radius:12px;background:rgba(255,255,255,.72);border:1px solid rgba(255,255,255,.55)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="display:flex;gap:14px;flex-wrap:wrap">
                                        <span><strong>Total Recent Gen:</strong> {total_gen_display}</span>
        </div>
                <div style="display:flex;gap:8px;flex-wrap:wrap">{tracking_status_html}{webhook_status_html}</div>
      </div>
            {sync_error_html}
    </section>
    """

    output_html = ""
    output_meta_html = ""
    if output:
        conf_download_href = "data:text/plain;charset=utf-8," + urllib.parse.quote(output["conf_content"])
        output_html = f"""
        <section style="margin-top:24px;padding:20px;border-radius:16px;background:rgba(255,255,255,.72);border:1px solid rgba(255,255,255,.55)">
          <h2 style="margin:0 0 12px 0">Generated Output</h2>
          <p style="margin:0 0 12px 0"><strong>Endpoint:</strong> {html.escape(output['endpoint'])}</p>
          <div style="display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 16px 0">
            <a href="{conf_download_href}" download="{output['conf_filename']}" style="padding:10px 14px;border-radius:999px;background:#111827;color:#fff;text-decoration:none">Download .conf</a>
            <a href="data:image/png;base64,{output['qr_b64']}" download="{output['qr_filename']}" style="padding:10px 14px;border-radius:999px;background:#111827;color:#fff;text-decoration:none">Download QR .png</a>
          </div>
          <img alt="WireGuard QR" src="data:image/png;base64,{output['qr_b64']}" style="max-width:280px;border-radius:12px;border:1px solid #e5e7eb" />
        </section>
        """
        output_meta_html = f"""
        <div id="generated-meta"
             data-ts="{output['timestamp']}"
             data-endpoint="{html.escape(output['endpoint'])}"
             data-conf="{html.escape(output['conf_filename'])}"
             data-conf-href="{html.escape(conf_download_href)}"
             data-qr="{html.escape(output['qr_filename'])}"
             data-qr-href="data:image/png;base64,{html.escape(output['qr_b64'])}"></div>
        """

    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>WARP FastAPI Generator</title>
      <style>
        body {{ font-family: Inter, Arial, sans-serif; background: #f3f4f6; margin: 0; color: #111827; }}
        .container {{ max-width: 960px; margin: 32px auto; padding: 0 16px; }}
        .card {{ background: rgba(255,255,255,.62); border: 1px solid rgba(255,255,255,.55); border-radius: 18px; padding: 20px; box-shadow: 0 8px 28px rgba(0,0,0,.06); }}
                h1 {{ font-size: 44px; line-height: 1.1; margin-bottom: 16px; }}
        input, select {{ width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #d1d5db; margin-top: 6px; box-sizing: border-box; }}
                label {{ display: block; font-weight: 600; margin-top: 10px; line-height: 1.25; }}
        .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
        .btn {{ margin-top: 16px; padding: 12px 16px; border: 0; border-radius: 999px; background: #111827; color: #fff; font-weight: 600; cursor: pointer; }}
        .btn-secondary {{ background: #374151; }}
        .actions {{ display:flex; gap:10px; flex-wrap:wrap; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border-bottom: 1px solid #e5e7eb; text-align: left; padding: 10px 8px; }}
                @media (max-width: 640px) {{
                    .container {{ margin: 16px auto; }}
                    .row {{ grid-template-columns: 1fr; }}
                    h1 {{ font-size: 36px; }}
                }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="card">
          <h1 style="margin-top:0">WARP FastAPI Generator</h1>
          <p style="margin-top:0;color:#374151">Generate secure WARP config with QR PNG and .conf using auto/select/custom endpoint IP.</p>
          {stats_html}
          {error_html}
          <form id="generate-form" method="post" action="/generate">
            <div class="row">
              <div>
                <label>Endpoint Port (default 500)</label>
                <input name="port" type="number" min="1" max="65535" value="{port}" />
              </div>
              <div>
                <label>Probe Timeout (seconds)</label>
                <input name="probe_timeout" type="number" step="0.1" min="0.1" value="{probe_timeout}" />
              </div>
            </div>

            <label style="margin-top:14px">IP Mode</label>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px">
              <label><input type="radio" name="mode" value="auto" {'checked' if mode == 'auto' else ''} style="width:auto;margin-right:6px" />Auto (first OK)</label>
              <label><input type="radio" name="mode" value="select" {'checked' if mode == 'select' else ''} style="width:auto;margin-right:6px" />Select from list</label>
              <label><input type="radio" name="mode" value="custom" {'checked' if mode == 'custom' else ''} style="width:auto;margin-right:6px" />Custom IP</label>
            </div>

            <label>Available IPs</label>
            <select name="selected_ip">
              {options}
            </select>

            <label>Custom IP</label>
            <input name="custom_ip" placeholder="e.g. 162.159.192.1" value="{html.escape(custom_ip)}" />

                        <div class="actions">
                            <button id="generate-btn" class="btn" type="submit">Generate</button>
                            <button class="btn btn-secondary" type="submit" formaction="/" formmethod="get">Check IP List</button>
                        </div>
          </form>
        </div>

        <section style="margin-top:20px" class="card">
          <h2 style="margin-top:0">Available IP Probe Result</h2>
          <table>
            <thead><tr><th>IP</th><th>Status</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>

        {output_html}

                <section style="margin-top:20px" class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
                        <h2 style="margin:0">Your Local Generation History</h2>
                        <button id="clear-history-btn" class="btn btn-secondary" style="margin-top:0" type="button">Clear History</button>
                    </div>
                    <table>
                        <thead><tr><th>Time</th><th>Endpoint</th><th>.conf</th><th>QR</th></tr></thead>
                        <tbody id="history-body"><tr><td colspan="4" style="color:#6b7280">No local history yet.</td></tr></tbody>
                    </table>
                </section>

                {output_meta_html}

                <section style="margin-top:20px" class="card">
                    <p style="margin:0 0 12px 0;color:#374151">MIT Licensed. This project is provided for educational purposes.</p>
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
                        <p style="margin:0;color:#374151">Like this project? Support and follow updates.</p>
                        <div style="display:flex;gap:10px;flex-wrap:wrap">
                            <a href="https://github.com/devtint/WarpConfGen" target="_blank" rel="noopener noreferrer" class="btn" style="margin-top:0;text-decoration:none;display:inline-block">⭐ Star the repo</a>
                            <a href="https://t.me/h3lpw1thvpn" target="_blank" rel="noopener noreferrer" class="btn btn-secondary" style="margin-top:0;text-decoration:none;display:inline-block">💬 Telegram</a>
                        </div>
                    </div>
                </section>
      </div>
            <script>
                (function () {{
                    const HISTORY_KEY = "warpgen_history_v1";
                    const SCROLL_BOTTOM_KEY = "warpgen_scroll_bottom_v1";
                    const HISTORY_LIMIT = 50;
                    const historyBody = document.getElementById("history-body");
                    const clearBtn = document.getElementById("clear-history-btn");
                    const generatedMeta = document.getElementById("generated-meta");
                    const generateForm = document.getElementById("generate-form");

                    function scrollToBottom() {{
                        window.scrollTo({{ top: document.body.scrollHeight, behavior: "smooth" }});
                    }}

                    function loadHistory() {{
                        try {{
                            const raw = localStorage.getItem(HISTORY_KEY);
                            if (!raw) return [];
                            const parsed = JSON.parse(raw);
                            return Array.isArray(parsed) ? parsed : [];
                        }} catch (e) {{
                            return [];
                        }}
                    }}

                    function saveHistory(items) {{
                        localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
                    }}

                    function escapeHtml(value) {{
                        return String(value)
                            .replaceAll("&", "&amp;")
                            .replaceAll("<", "&lt;")
                            .replaceAll(">", "&gt;")
                            .replaceAll('"', "&quot;")
                            .replaceAll("'", "&#39;");
                    }}

                    function renderHistory(items) {{
                        if (!items.length) {{
                            historyBody.innerHTML = '<tr><td colspan="4" style="color:#6b7280">No local history yet.</td></tr>';
                            return;
                        }}

                        historyBody.innerHTML = items
                            .map((item) => {{
                                const dt = new Date(item.timestamp || Date.now());
                                const confHref = item.conf_href || '';
                                const qrHref = item.qr_href || '';
                                return `
                                <tr>
                                  <td>${{escapeHtml(dt.toLocaleString())}}</td>
                                  <td>${{escapeHtml(item.endpoint || '')}}</td>
                                  <td>
                                    ${{confHref ? `<a href="${{confHref}}" download="${{escapeHtml(item.conf_filename || '')}}" style="padding:6px 10px;border-radius:8px;background:#111827;color:#fff;text-decoration:none">Download</a>` : escapeHtml(item.conf_filename || '')}}
                                  </td>
                                  <td>
                                    ${{qrHref ? `<a href="${{qrHref}}" target="_blank" rel="noopener" style="padding:6px 10px;border-radius:8px;background:#06b6d4;color:#fff;text-decoration:none;margin-right:6px">View</a><a href="${{qrHref}}" download="${{escapeHtml(item.qr_filename || '')}}" style="padding:6px 10px;border-radius:8px;background:#111827;color:#fff;text-decoration:none">Download</a>` : escapeHtml(item.qr_filename || '')}}
                                  </td>
                                </tr>`;
                            }})
                            .join("");
                    }}

                    let historyItems = loadHistory();

                    if (generatedMeta) {{
                        historyItems.unshift({{
                            timestamp: Number(generatedMeta.dataset.ts || Date.now()),
                            endpoint: generatedMeta.dataset.endpoint || "",
                            conf_filename: generatedMeta.dataset.conf || "",
                            conf_href: generatedMeta.dataset.confHref || document.querySelector('a[download$=".conf"]')?.href || "",
                            qr_filename: generatedMeta.dataset.qr || "",
                            qr_href: generatedMeta.dataset.qrHref || document.querySelector('a[download$=".png"]')?.href || "",
                        }});
                        historyItems = historyItems.slice(0, HISTORY_LIMIT);
                        saveHistory(historyItems);
                    }}

                    if (sessionStorage.getItem(SCROLL_BOTTOM_KEY) === "1" || generatedMeta) {{
                        sessionStorage.removeItem(SCROLL_BOTTOM_KEY);
                        setTimeout(() => {{
                            scrollToBottom();
                        }}, 60);
                    }}

                    renderHistory(historyItems);

                    clearBtn?.addEventListener("click", () => {{
                        localStorage.removeItem(HISTORY_KEY);
                        renderHistory([]);
                    }});

                    generateForm?.addEventListener("submit", () => {{
                        sessionStorage.setItem(SCROLL_BOTTOM_KEY, "1");
                        scrollToBottom();
                    }});
                }})();
            </script>
    </body>
    </html>
    """


def select_endpoint_ip(mode, selected_ip, custom_ip, candidate_results):
    if mode == "custom":
        if not custom_ip:
            raise ValueError("Custom IP is required when mode is custom")
        return validate_ip(custom_ip)

    if mode == "select":
        if not selected_ip:
            raise ValueError("Select an IP from the list")
        available = {item["ip"] for item in candidate_results}
        if selected_ip not in available:
            raise ValueError("Selected IP is not in available list")
        return selected_ip

    working = [item["ip"] for item in candidate_results if item["ok"]]
    if not working:
        if candidate_results:
            return candidate_results[0]["ip"]
        raise ValueError("No candidate IP available for auto mode")
    return working[0]


@app.get("/", response_class=HTMLResponse)
def index(port: int = 500, probe_timeout: float = 1.0):
    sync_stats_from_webhook()
    candidate_results = collect_candidate_results(port=port, timeout_sec=probe_timeout)
    selected_ip = candidate_results[0]["ip"] if candidate_results else ""
    return render_page(
        candidate_results=candidate_results,
        selected_ip=selected_ip,
        port=port,
        probe_timeout=probe_timeout,
        stats=get_generation_stats(),
    )


@app.post("/generate", response_class=HTMLResponse)
def generate(
    request: Request,
    mode: str = Form("auto"),
    selected_ip: str = Form(""),
    custom_ip: str = Form(""),
    port: int = Form(500),
    probe_timeout: float = Form(1.0),
):
    candidate_results = collect_candidate_results(port=port, timeout_sec=probe_timeout)

    try:
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
        endpoint_ip = select_endpoint_ip(mode=mode, selected_ip=selected_ip, custom_ip=custom_ip.strip(), candidate_results=candidate_results)
        output = generate_warp_payload(endpoint_ip=endpoint_ip, endpoint_port=port)
        webhook_ok = send_generation_webhook(
            client_ip=get_client_ip(request),
            mode=mode,
            endpoint=output["endpoint"],
            port=port,
        )
        record_generation_stats(webhook_ok)
        sync_stats_from_webhook()
        return render_page(
            candidate_results=candidate_results,
            output=output,
            mode=mode,
            selected_ip=selected_ip,
            custom_ip=custom_ip,
            port=port,
            probe_timeout=probe_timeout,
            stats=get_generation_stats(),
            webhook_status=webhook_ok["status"],
        )
    except Exception as e:
        return render_page(
            candidate_results=candidate_results,
            error_text=str(e),
            mode=mode,
            selected_ip=selected_ip,
            custom_ip=custom_ip,
            port=port,
            probe_timeout=probe_timeout,
            stats=get_generation_stats(),
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)