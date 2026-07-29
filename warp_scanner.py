#!/usr/bin/env python3
"""
WarpGen WARP Endpoint Scanner
Finds the fastest Cloudflare WARP endpoints for your network.

Usage:
    pip install colorama
    python warp_scanner.py
    python warp_scanner.py --max-ips 200
    python warp_scanner.py --workers 100 --timeout 1.5
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, UTC

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        GREEN = YELLOW = RED = CYAN = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ── Config ──────────────────────────────────────────────────────────────────

CF_RANGES = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
]

CF_PORTS = [500, 2408, 1701, 4500]

# ── Probe ────────────────────────────────────────────────────────────────────

def ping_ip(ip: str, timeout: float) -> float | None:
    """Ping an IP and return average latency in ms, or None if unreachable."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", "2", "-w", str(int(timeout * 1000)), ip]
        pat = re.compile(r"Average\s*=\s*(\d+)ms", re.IGNORECASE)
    else:
        cmd = ["ping", "-c", "2", "-W", str(int(timeout)), ip]
        pat = re.compile(r"[\d.]+/([\d.]+)/[\d.]+")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 2)
        if r.returncode != 0:
            return None
        m = pat.search(r.stdout)
        return float(m.group(1)) if m else None
    except Exception:
        return None

# ── Scan ─────────────────────────────────────────────────────────────────────

_lock    = threading.Lock()
_done    = 0
_found   = 0

def _bar(total: int) -> None:
    pct    = _done / total * 100
    filled = int(30 * _done / total)
    bar    = "#" * filled + "." * (30 - filled)
    sys.stdout.write(
        f"\r  [{bar}] {pct:5.1f}%  {_done}/{total}  "
        f"found {Fore.GREEN}{_found}{Style.RESET_ALL}   "
    )
    sys.stdout.flush()

def scan(ranges, ports, workers, timeout, max_ips, top_n) -> list[dict]:
    global _done, _found
    _done = _found = 0

    ips = []
    for cidr in ranges:
        ips.extend(str(h) for h in ipaddress.IPv4Network(cidr, strict=False).hosts())

    if max_ips:
        import random; random.shuffle(ips)
        ips = ips[:max_ips]
    else:
        import random; random.shuffle(ips)

    total   = len(ips)
    results = []

    print(f"\n  Scanning {total:,} IPs  |  ports: {ports}  |  workers: {workers}\n")
    print(f"  {'Endpoint':<24}  {'Latency':>9}  Quality")
    print("  " + "-" * 50)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping_ip, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip      = futures[future]
            latency = future.result()
            with _lock:
                _done += 1
                if latency is not None:
                    _found += 1
                    for port in ports:
                        results.append({"ip": ip, "port": port,
                                        "endpoint": f"{ip}:{port}",
                                        "latency_ms": round(latency, 1)})
                    # print first port as preview, clear progress first
                    sys.stdout.write("\r" + " " * 70 + "\r")
                    lat   = latency
                    color = Fore.GREEN if lat < 80 else Fore.YELLOW if lat < 200 else Fore.RED
                    qual  = "Excellent" if lat < 80 else "Good" if lat < 200 else "Fair" if lat < 400 else "Slow"
                    print(f"  {color}{ip:<24}{Style.RESET_ALL}  {color}{lat:>7.1f} ms{Style.RESET_ALL}  {qual}")
                if _done % 5 == 0 or _done == total:
                    _bar(total)

    sys.stdout.write("\r" + " " * 70 + "\r")
    results.sort(key=lambda r: r["latency_ms"])
    return results[:top_n]

# ── Output ────────────────────────────────────────────────────────────────────

def summary(results: list[dict]) -> None:
    if not results:
        print("\n  No working endpoints found.")
        print("  Try: --timeout 3.0  or  --workers 50\n")
        return

    print(f"\n  {'='*55}")
    print(f"  TOP WARP ENDPOINTS FOR YOUR NETWORK")
    print(f"  {'='*55}")
    print(f"  {'#':<4} {'Endpoint':<24} {'Latency':>10}  Quality")
    print(f"  {'-'*52}")

    for i, r in enumerate(results, 1):
        lat   = r["latency_ms"]
        color = Fore.GREEN if lat < 80 else Fore.YELLOW if lat < 200 else Fore.RED
        qual  = "Excellent" if lat < 80 else "Good" if lat < 200 else "Fair" if lat < 400 else "Slow"
        print(f"  {i:<4} {color}{r['endpoint']:<24}{Style.RESET_ALL}  {color}{lat:>7.1f} ms{Style.RESET_ALL}  {qual}")

    best = results[0]
    print(f"\n  Best endpoint: {Fore.GREEN}{best['endpoint']}{Style.RESET_ALL}  ({best['latency_ms']} ms)")
    print(f"  Paste it into WarpGen Custom IP -> https://warp-conf-gen.vercel.app\n")

def save(results: list[dict], path: str) -> None:
    with open(path, "w") as f:
        json.dump({"generated": datetime.now(UTC).isoformat(),
                   "count": len(results), "results": results}, f, indent=2)
    print(f"  Saved -> {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def _get_int_input(prompt: str, default: int, min_val: int = 1, max_val: int | None = None) -> int:
    try:
        val = input(prompt).strip()
        if not val:
            return default
        num = int(val)
        if num < min_val:
            print(f"  [!] Value too low. Using minimum: {min_val}")
            return min_val
        if max_val is not None and num > max_val:
            print(f"  [!] Capping value at soft limit: {max_val}")
            return max_val
        return num
    except ValueError:
        print(f"  [!] Invalid format. Using default: {default}")
        return default

def _get_float_input(prompt: str, default: float, min_val: float = 0.1, max_val: float = 10.0) -> float:
    try:
        val = input(prompt).strip()
        if not val:
            return default
        num = float(val)
        if num < min_val:
            print(f"  [!] Value too low. Using minimum: {min_val}")
            return min_val
        if num > max_val:
            print(f"  [!] Capping value at soft limit: {max_val}")
            return max_val
        return num
    except ValueError:
        print(f"  [!] Invalid format. Using default: {default}")
        return default

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Set default scanner configurations
    workers = 20
    timeout = 1.5
    max_ips = 100  # Default to 100 for fast mobile scans when run interactively
    top = 20
    out = None

    # If no flags are provided (e.g. when run via GUI run button in Pydroid 3),
    # prompt the user interactively inside the terminal.
    if len(sys.argv) == 1:
        print("\n=== WarpGen Scanner Configuration ===")
        print("Press [Enter] to use the default value.\n")
        try:
            # 1. Limit IPs (0 for all, soft limit of 1792 total usable IPs)
            val = input("1. Limit IPs to scan [Default: 100, Enter 0 for all]: ").strip()
            if not val:
                max_ips = 100
            else:
                try:
                    num = int(val)
                    if num == 0:
                        max_ips = None
                    elif num < 0:
                        print("  [!] Negative value. Using default: 100")
                        max_ips = 100
                    else:
                        max_ips = num
                except ValueError:
                    print("  [!] Invalid format. Using default: 100")
                    max_ips = 100

            # 2. Workers (soft max limit of 100 threads)
            workers = _get_int_input("2. Thread count (Speed) [Default: 20, Soft Max: 100]: ", 20, 1, 100)

            # 3. Timeout (soft max limit of 10.0 seconds)
            timeout = _get_float_input("3. Timeout per ping (Seconds) [Default: 1.5, Soft Max: 10.0]: ", 1.5, 0.1, 10.0)

            # 4. Top Results (soft max limit of 100)
            top = _get_int_input("4. Top results count to show [Default: 20, Soft Max: 100]: ", 20, 1, 100)

        except (KeyboardInterrupt, SystemExit):
            print("\nExiting...")
            sys.exit(0)
    else:
        p = argparse.ArgumentParser(description="Cloudflare WARP endpoint scanner")
        p.add_argument("--workers",  type=int,   default=20,   help="Parallel threads (default: 20)")
        p.add_argument("--timeout",  type=float, default=1.5,  help="Ping timeout seconds (default: 1.5)")
        p.add_argument("--max-ips",  type=int,   default=None, help="Limit number of IPs to scan")
        p.add_argument("--top",      type=int,   default=20,   help="Top N results (default: 20)")
        p.add_argument("--out",      type=str,   default=None, help="Save results to JSON file")
        args = p.parse_args()
        workers = args.workers
        timeout = args.timeout
        max_ips = args.max_ips
        top = args.top
        out = args.out

    results = scan(CF_RANGES, CF_PORTS, workers, timeout, max_ips, top)
    summary(results)

    out_file = out or f"warp_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save(results, out_file)

if __name__ == "__main__":
    main()
