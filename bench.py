#!/usr/bin/env python3
"""Measure tailscale-service over one or more network paths. Standard library only; copy it to any machine.

    python3 bench.py https://box.your-tailnet.ts.net:8443
    python3 bench.py http://192.168.1.20:8080 http://100.101.102.103:8080 https://box.your-tailnet.ts.net:8443

For each URL, over one keep-alive connection:
  route     direct or relayed, and the link's round trip (tailscale ping), for tailnet addresses
  connect   TCP setup, plus the TLS handshake on https. Paid once per connection.
  tiny      GET /healthz (12 bytes): what each request costs over the link round trip
  api       GET /api/events?limit=20 (~3 KB): p50 / p95 / p99
  feed      publish an event, time until it arrives on the live feed. Needs write access:
            SERVICE_TOKEN in the environment or a .env next to this file, or your login in WRITERS
  export    GET /api/export, Mbit/s (start the service with --demo-data 200000 for a real-sized file)
The first URL is the baseline. Every other URL is compared against it.
"""
import argparse, http.client, ipaddress, json, os, secrets, shutil, statistics, subprocess, time
from pathlib import Path
from urllib.parse import urlparse

BUF = memoryview(bytearray(1 << 20))
TS_CLI = next((c for c in ("/Applications/Tailscale.app/Contents/MacOS/Tailscale", shutil.which("tailscale"))
               if c and os.path.exists(c)), None)


def env_token():
    if os.environ.get("SERVICE_TOKEN"):
        return os.environ["SERVICE_TOKEN"]
    env = Path(__file__).resolve().with_name(".env")
    for line in env.read_text().splitlines() if env.exists() else []:
        key, _, value = line.partition("=")
        if key.strip() == "SERVICE_TOKEN" and value.strip().strip("'\""):
            return value.strip().strip("'\"")
    return ""


def connect(url, timeout=60):
    u = urlparse(url)
    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = cls(u.hostname, u.port, timeout=timeout)   # https verifies the certificate. Never turn that off.
    conn.prefix = u.path.rstrip("/")
    return conn


def fetch(conn, path):
    """GET and drain the body; returns its length."""
    conn.request("GET", conn.prefix + path)
    r = conn.getresponse()
    if r.status != 200:
        raise SystemExit(f"{conn.host}{conn.prefix}{path}: HTTP {r.status} {r.read()[:200]!r}")
    total = 0
    while True:
        k = r.readinto(BUF)
        if not k:
            return total
        total += k


def post(conn, path, obj, token):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    conn.request("POST", conn.prefix + path, json.dumps(obj).encode(), headers)
    r = conn.getresponse()
    r.read()
    return r.status


def feed_latency(url, conn, n, token):
    """Publish n events on conn; time each one until it arrives on /feed over a second connection."""
    stream = connect(url, timeout=10)
    stream.request("GET", stream.prefix + "/feed")
    s = stream.getresponse()
    if s.status != 200:
        return [], f"feed: HTTP {s.status}"
    out = []
    try:
        while not s.readline().startswith(b": connected"):   # subscribed from here on
            pass
        for _ in range(n):
            nonce = secrets.token_hex(8).encode()
            t = time.perf_counter()
            code = post(conn, "/api/events", {"type": "bench", "message": nonce.decode()}, token)
            if code != 201:
                return [], ("feed: skipped, no write access (set SERVICE_TOKEN, or add your login to WRITERS)"
                            if code == 401 else f"feed: POST answered HTTP {code}")
            while True:
                line = s.readline()
                if not line:
                    return out, "feed: the stream closed"
                if nonce in line:
                    break
            out.append(time.perf_counter() - t)
    except OSError:
        return out, "feed: an event took over 10 s to arrive (is a proxy buffering the stream?)"
    finally:
        stream.close()
    return out, ""


def route(host):
    """('direct' | 'relay:<region>' | '-', median link round trip in ms) from `tailscale ping`, for tailnet hosts."""
    try:
        tailnet = host.endswith(".ts.net") or ipaddress.ip_address(host) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        tailnet = False
    if not tailnet or not TS_CLI:
        return "-", None
    try:
        out = subprocess.run([TS_CLI, "ping", "--until-direct=false", "-c", "10", host],
                             capture_output=True, text=True, timeout=60).stdout
    except subprocess.TimeoutExpired:
        return "?", None
    # pong from box (100.101.102.103) via 203.0.113.5:41641 in 12ms   |   ... via DERP(nyc) in 40ms
    pongs = [p for p in out.splitlines() if p.startswith("pong") and " in " in p]
    if not pongs:
        return "local" if "local" in out.lower() else "?", None
    ms = statistics.median(float(p.rsplit(" in ", 1)[1].strip().rstrip("ms")) for p in pongs)
    via = pongs[-1].split(" via ", 1)[1].split()[0]
    return ("relay:" + via[5:-1] if via.startswith("DERP(") else "direct"), ms


def pct(xs):
    if len(xs) < 2:
        return None
    q = statistics.quantiles(xs, n=100)
    return q[49] * 1e3, q[94] * 1e3, q[98] * 1e3


def measure(url, n=300, feed_n=50, runs=3, token=""):
    conn = connect(url)
    t = time.perf_counter()
    conn.connect()
    connect_ms = (time.perf_counter() - t) * 1e3
    for _ in range(5):
        fetch(conn, "/api/events?limit=20")   # warm-up
    tiny, api = [], []
    for _ in range(n):
        t = time.perf_counter()
        fetch(conn, "/healthz")
        tiny.append(time.perf_counter() - t)
        t = time.perf_counter()
        fetch(conn, "/api/events?limit=20")
        api.append(time.perf_counter() - t)
    feed, note = feed_latency(url, conn, feed_n, token) if feed_n else ([], "")
    size, speeds = 0, []
    for _ in range(runs):
        t = time.perf_counter()
        size = fetch(conn, "/api/export")
        speeds.append(size * 8 / (time.perf_counter() - t) / 1e6)
    conn.request("GET", conn.prefix + "/whoami")
    who = json.loads(conn.getresponse().read())
    conn.close()
    return {"connect": connect_ms, "tiny": pct(tiny), "api": pct(api), "feed": pct(feed), "note": note,
            "export_mb": size / 1e6, "mbps": statistics.median(speeds), "who": who.get("login") or "-"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("urls", nargs="+", help="the service's base URLs; the first one is the baseline")
    ap.add_argument("-n", type=int, default=200, help="requests of each kind per URL (default 200)")
    ap.add_argument("--feed", type=int, default=50, help="events published per URL for the feed test; 0 skips it")
    a = ap.parse_args()
    token = env_token()

    rows = []
    for url in a.urls:
        print(f"measuring {url} ...", flush=True)
        r = measure(url, a.n, a.feed, token=token)
        r["route"], r["link"] = route(urlparse(url).hostname)
        rows.append((url, r))

    ms = lambda v: f"{v:.2f}ms" if v is not None else "-"
    w = max(len(u) for u in a.urls)
    print(f"\n{'path':<{w}}  {'route':<12} {'link rtt':>9} {'connect':>9} {'tiny p50':>9} {'api p50':>9} {'p95':>9} {'p99':>9}"
          f" {'feed p50':>9} {'export':>13}  tailscale identity")
    for url, r in rows:
        api, feed = r["api"], r["feed"]
        print(f"{url:<{w}}  {r['route']:<12} {ms(r['link']):>9} {ms(r['connect']):>9} {ms(r['tiny'][0]):>9} {ms(api[0]):>9} {ms(api[1]):>9}"
              f" {ms(api[2]):>9} {ms(feed[0] if feed else None):>9} {r['mbps']:>8.0f} Mb/s  {r['who']}")
    print()
    for url, r in rows:
        if r["note"]:
            print(f"{url}: {r['note']}")
        if r["link"] is not None:
            print(f"{url}: each request costs {r['tiny'][0] - r['link']:+.2f} ms over the link's round trip "
                  f"(Tailscale + TLS + the service). Bigger replies add time for the extra packets on any network.")
        if r["export_mb"] < 5:
            print(f"{url}: the export is only {r['export_mb']:.1f} MB; start the service with --demo-data 200000 "
                  f"for a meaningful throughput number")
    base_url, base = rows[0]
    for url, r in rows[1:]:
        print(f"{url} vs {base_url}: {r['tiny'][0] - base['tiny'][0]:+.2f} ms per request, "
              f"{r['api'][0] - base['api'][0]:+.2f} ms per API call (p50), "
              f"{100 * (r['mbps'] / base['mbps'] - 1):+.0f}% throughput, "
              f"{r['connect'] - base['connect']:+.1f} ms once per connection")


if __name__ == "__main__":
    main()
