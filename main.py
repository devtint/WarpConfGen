import base64
import html
import io
import ipaddress
import socket
import time
import urllib.parse

import qrcode
import requests
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
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


app = FastAPI(title="WARP Generator")


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

    address_param = urllib.parse.quote(f"{ipv4},{ipv6}")
    private_key_encoded = urllib.parse.quote(private_key_b64)
    reserved_param = f"{reserved[0]},{reserved[1]},{reserved[2]}"
    endpoint = f"{endpoint_ip}:{endpoint_port}"

    timestamp = int(time.time() * 1000)
    uri = (
        f"wireguard://{private_key_encoded}@{endpoint}?"
        f"address={address_param}&"
        f"presharedkey=&"
        f"reserved={reserved_param}&"
        f"publickey={urllib.parse.quote(PEER_PUBLIC_KEY)}&"
        f"mtu=1280#{timestamp}"
    )

    conf_content = build_wireguard_conf(private_key_b64=private_key_b64, ipv4=ipv4, ipv6=ipv6, endpoint=endpoint)
    qr_b64 = build_qr_base64(conf_content)

    return {
        "timestamp": timestamp,
        "uri": uri,
        "conf_content": conf_content,
        "conf_filename": f"warp-{timestamp}.conf",
        "qr_filename": f"warp-{timestamp}.png",
        "qr_b64": qr_b64,
        "endpoint": endpoint,
    }


def render_page(candidate_results, output=None, error_text="", mode="auto", selected_ip="", custom_ip="", port=500, probe_timeout=1.0):
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

    output_html = ""
    if output:
        conf_download_href = "data:text/plain;charset=utf-8," + urllib.parse.quote(output["conf_content"])
        output_html = f"""
        <section style="margin-top:24px;padding:20px;border-radius:16px;background:rgba(255,255,255,.72);border:1px solid rgba(255,255,255,.55)">
          <h2 style="margin:0 0 12px 0">Generated Output</h2>
          <p style="margin:0 0 12px 0"><strong>Endpoint:</strong> {html.escape(output['endpoint'])}</p>
          <p style="margin:0 0 12px 0;word-break:break-all"><strong>URI:</strong><br>{html.escape(output['uri'])}</p>
          <div style="display:flex;gap:12px;flex-wrap:wrap;margin:12px 0 16px 0">
            <a href="{conf_download_href}" download="{output['conf_filename']}" style="padding:10px 14px;border-radius:999px;background:#111827;color:#fff;text-decoration:none">Download .conf</a>
            <a href="data:image/png;base64,{output['qr_b64']}" download="{output['qr_filename']}" style="padding:10px 14px;border-radius:999px;background:#111827;color:#fff;text-decoration:none">Download QR .png</a>
          </div>
          <img alt="WireGuard QR" src="data:image/png;base64,{output['qr_b64']}" style="max-width:280px;border-radius:12px;border:1px solid #e5e7eb" />
        </section>
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
          <p style="margin-top:0;color:#374151">Generate key, URI, QR PNG, and .conf with auto/select/custom endpoint IP.</p>
          {error_html}
          <form method="post" action="/generate">
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
                            <button class="btn" type="submit">Generate</button>
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
    candidate_results = collect_candidate_results(port=port, timeout_sec=probe_timeout)
    selected_ip = candidate_results[0]["ip"] if candidate_results else ""
    return render_page(candidate_results=candidate_results, selected_ip=selected_ip, port=port, probe_timeout=probe_timeout)


@app.post("/generate", response_class=HTMLResponse)
def generate(
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
        return render_page(
            candidate_results=candidate_results,
            output=output,
            mode=mode,
            selected_ip=selected_ip,
            custom_ip=custom_ip,
            port=port,
            probe_timeout=probe_timeout,
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
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)