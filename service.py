#!/usr/bin/env python3
"""tailscale-service: a private event hub that only your tailnet can reach.

    python3 service.py --serve      # listens on 127.0.0.1:8080, published at https://<this-machine>.<tailnet>.ts.net:8443

  POST /api/events          webhook in: servers, scripts and jobs push events     (token or WRITERS)
  GET  /api/events          REST API: search and page through events
  GET  /api/events/<id>     one event
  GET  /feed                live data feed (Server-Sent Events), resumable
  GET  /api/export          everything as NDJSON, for analysts, backups and bulk loads
  GET  /upstream/<path>     gateway to a vendor API: the vendor key never leaves this machine
  GET  /whoami              who Tailscale says you are
  GET  /healthz             liveness

Settings come from environment variables or a .env file next to this script (see .env.example).
Standard library only, Python 3.8+.
"""
import argparse, hmac, json, os, random, secrets, shutil, signal, socket, sqlite3, ssl, subprocess, sys, threading, time
import urllib.error, urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

HERE = Path(__file__).resolve().parent
ENV_FILE = HERE / ".env"


def load_env(path=ENV_FILE):
    """KEY=value lines from .env. Real environment variables win; empty values (KEY=) are skipped."""
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            value = value.strip().strip("'\"")
            if sep and value and key.strip() and not key.lstrip().startswith("#"):
                os.environ.setdefault(key.strip(), value)


load_env()
DB_PATH = os.environ.get("DB_PATH") or str(HERE / "events.db")
WRITERS = {w.strip().lower() for w in os.environ.get("WRITERS", "").split(",") if w.strip()}
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "").rstrip("/")
UPSTREAM_HEADER = os.environ.get("UPSTREAM_HEADER", "Authorization")
UPSTREAM_KEY = os.environ.get("UPSTREAM_KEY", "")
UPSTREAM_TTL = float(os.environ.get("UPSTREAM_CACHE_SECONDS", "60"))
MAX_BODY = 64 * 1024              # one webhook event
MAX_UPSTREAM = 20 * 1024 * 1024   # one vendor reply


# --- storage: SQLite, one connection per request (connections can't be shared between threads) ----------------

def run(sql, args=()):
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        with c:   # commits
            cur = c.execute(sql, args)
            return cur.fetchall(), cur.lastrowid
    finally:
        c.close()


NEW = threading.Condition()   # feed readers wait on this for LATEST to move
LATEST = [0]                  # newest event id
EXPORT = (-1, b"")            # (LATEST it was built at, NDJSON bytes)


def init_db():
    run("PRAGMA journal_mode=WAL")   # readers don't block the writer
    run("""CREATE TABLE IF NOT EXISTS events (
             id INTEGER PRIMARY KEY, at TEXT NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL,
             message TEXT NOT NULL DEFAULT '', data TEXT NOT NULL DEFAULT '{}')""")
    LATEST[0] = run("SELECT COALESCE(MAX(id), 0) FROM events")[0][0][0]


def iso(ts=None):
    return datetime.fromtimestamp(time.time() if ts is None else ts, timezone.utc).isoformat(timespec="milliseconds")[:-6] + "Z"


def as_json(r):
    return {"id": r["id"], "at": r["at"], "source": r["source"], "type": r["type"],
            "message": r["message"], "data": json.loads(r["data"])}


def add_event(source, type_, message="", data=None):
    _, eid = run("INSERT INTO events (at, source, type, message, data) VALUES (?, ?, ?, ?, ?)",
                 (iso(), source, type_, message, json.dumps(data if data is not None else {})))
    with NEW:
        LATEST[0] = max(LATEST[0], eid)
        NEW.notify_all()
    return eid


def export_bytes():
    """Every event as NDJSON, rebuilt only after something changed."""
    # ponytail: built in memory; stream it from the database once the table outgrows RAM
    global EXPORT
    latest = LATEST[0]
    if EXPORT[0] != latest:
        rows, _ = run("SELECT * FROM events WHERE id <= ? ORDER BY id", (latest,))
        EXPORT = (latest, b"".join(json.dumps(as_json(r)).encode() + b"\n" for r in rows))
    return EXPORT[1]


def seed(n):
    """n sample events over the last 30 days, so search, paging, the feed and the export have real-sized data."""
    kinds = [("backup.finished", "nightly backup finished"), ("job.failed", "ETL job failed: timeout reading source"),
             ("deploy", "deployed build to production"), ("login.failed", "failed SSH login"),
             ("disk.usage", "disk usage report"), ("feed.item", "new indicator from the threat feed")]
    hosts = ["nas", "ci-runner", "web-1", "web-2", "db-1", "laptop"]
    rng, start = random.Random(42), time.time() - 30 * 86400
    rows = []
    for i in range(n):
        kind, msg = rng.choice(kinds)
        rows.append((iso(start + i * 30 * 86400 / n), rng.choice(hosts), kind, msg,
                     json.dumps({"duration_ms": rng.randrange(9000), "bytes": rng.randrange(10 ** 9), "seq": i})))
    c = sqlite3.connect(DB_PATH)
    with c:
        c.executemany("INSERT INTO events (at, source, type, message, data) VALUES (?, ?, ?, ?, ?)", rows)
    c.close()
    init_db()
    print(f"added {n} sample events")


# --- vendor gateway --------------------------------------------------------------------------------------------

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None   # following one would carry the vendor key to wherever it points


VENDOR = urllib.request.build_opener(_NoRedirects)
CACHE = {}   # url -> (expires, status, content type, body)


def fetch_upstream(path, query):
    """GET UPSTREAM_URL/<path>?<query> with the vendor key attached. Returns (status, content type, body, cached)."""
    target = f"{UPSTREAM_URL}/{path}" + (f"?{query}" if query else "")
    if urlparse(target).netloc != urlparse(UPSTREAM_URL).netloc or ".." in unquote(path).split("/"):
        return 400, "application/json", b'{"error": "bad upstream path"}', False
    hit = CACHE.get(target)
    if hit and hit[0] > time.monotonic():
        return hit[1], hit[2], hit[3], True
    req = urllib.request.Request(target, headers={"User-Agent": "tailscale-service", "Accept": "application/json, */*"})
    if UPSTREAM_KEY:
        req.add_header(UPSTREAM_HEADER, UPSTREAM_KEY)
    try:
        with VENDOR.open(req, timeout=30) as r:
            status, ctype, body = r.status, r.headers.get("Content-Type", ""), r.read(MAX_UPSTREAM + 1)
    except urllib.error.HTTPError as e:   # 4xx/5xx and refused redirects: pass the vendor's answer through
        status, ctype, body = e.code, e.headers.get("Content-Type", ""), e.read(MAX_UPSTREAM + 1)
    except OSError as e:
        return 502, "application/json", json.dumps({"error": f"vendor unreachable: {e}"}).encode(), False
    if len(body) > MAX_UPSTREAM:
        return 502, "application/json", b'{"error": "vendor reply over 20 MB"}', False
    if status == 200 and UPSTREAM_TTL > 0:
        if len(CACHE) >= 1000:
            CACHE.clear()   # ponytail: crude bound; an LRU if the hit rate ever matters
        CACHE[target] = (time.monotonic() + UPSTREAM_TTL, status, ctype, body)
    return status, ctype or "application/octet-stream", body, False


# --- HTTP ------------------------------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"    # keep-alive: clients pay the TLS handshake once, not per request
    disable_nagle_algorithm = True   # headers and body are two writes; with Nagle that can stall ~40 ms
    server_version, sys_version = "tailscale-service", ""

    # who is calling

    def via_serve(self):
        """Loopback = tailscale serve (or this machine). Only then are the Tailscale-* headers real."""
        return self.client_address[0] == "127.0.0.1"

    def parse_request(self):
        """Loopback requests must name this service in Host. Anything else is a web page using DNS rebinding."""
        if not super().parse_request():
            return False
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if self.via_serve() and host not in ("127.0.0.1", "localhost") and not host.endswith(".ts.net"):
            self.close_connection = True
            self.reply(421, {"error": "unexpected Host header"})
            return False
        return True

    def identity(self):
        return self.headers.get("Tailscale-User-Login") if self.via_serve() else None

    def caller_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "") if self.via_serve() else ""
        return fwd.split(",")[0].strip() or self.client_address[0]

    def may_write(self):
        token = os.environ.get("SERVICE_TOKEN", "")
        sent = self.headers.get("Authorization", "")
        if token and hmac.compare_digest(sent.encode(), f"Bearer {token}".encode()):
            return True
        who = self.identity()
        return bool(who and who.lower() in WRITERS)

    # routes

    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, parse_qs(url.query)
        if path == "/healthz":
            return self.reply(200, {"ok": True})
        if path == "/whoami":
            return self.reply(200, {"via_tailscale_serve": self.via_serve(), "login": self.identity(),
                                    "name": self.headers.get("Tailscale-User-Name") if self.via_serve() else None,
                                    "ip": self.caller_ip(), "can_write": self.may_write()})
        if path == "/api/events":
            return self.list_events(q)
        if path.startswith("/api/events/"):
            rows = []
            if path[12:].isdigit():
                rows, _ = run("SELECT * FROM events WHERE id = ?", (int(path[12:]),))
            return self.reply(200, as_json(rows[0])) if rows else self.reply(404, {"error": "no such event"})
        if path == "/api/export":
            return self.send_body(200, export_bytes(), "application/x-ndjson")
        if path == "/feed":
            return self.feed(q)
        if path.startswith("/upstream/"):
            if not UPSTREAM_URL:
                return self.reply(503, {"error": "the vendor gateway is off: set UPSTREAM_URL (and UPSTREAM_KEY) in .env"})
            status, ctype, body, cached = fetch_upstream(path[10:], url.query)
            # sandbox: vendor HTML or scripts can't run as this origin (where WRITERS identities can post)
            return self.send_body(status, body, ctype, [("X-Cache", "hit" if cached else "miss"),
                                                        ("Content-Security-Policy", "sandbox; default-src 'none'"),
                                                        ("X-Content-Type-Options", "nosniff")])
        self.reply(404, {"error": "unknown path; see README.md for the API"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/events":
            return self.reply(404, {"error": "POST /api/events"})
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            n = -1
        if not 0 < n <= MAX_BODY:
            self.close_connection = True   # the unread body would otherwise be parsed as the next request
            return self.reply(413 if n > MAX_BODY else 411, {"error": "send a JSON body up to 64 KB, with Content-Length"})
        raw = self.rfile.read(n)
        if not self.may_write():
            return self.reply(401, {"error": "send Authorization: Bearer <SERVICE_TOKEN>, or be listed in WRITERS"})
        if not self.headers.get("Content-Type", "").startswith("application/json"):   # blocks cross-site form posts
            return self.reply(415, {"error": "send Content-Type: application/json"})
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        if not isinstance(body, dict) or not str(body.get("type") or "").strip():
            return self.reply(400, {"error": 'body must be a JSON object with at least "type"'})
        data = body.get("data")
        eid = add_event(str(body.get("source") or self.identity() or self.caller_ip())[:100],
                        str(body["type"]).strip()[:100], str(body.get("message") or "")[:2000],
                        data if isinstance(data, (dict, list)) else {})
        self.reply(201, {"id": eid})

    def list_events(self, q):
        def arg(k):
            return (q.get(k) or [""])[0]
        try:
            limit = min(max(int(arg("limit") or 50), 1), 500)
            after, before = int(arg("after") or 0), int(arg("before") or 0)
        except ValueError:
            return self.reply(400, {"error": "limit, after and before must be numbers"})
        where, args = ["id > ?"], [after]
        if before:
            where.append("id < ?")
            args.append(before)
        for col in ("source", "type"):
            if arg(col):
                where.append(f"{col} = ?")
                args.append(arg(col))
        if arg("q"):
            where.append("(message LIKE ? OR data LIKE ?)")
            args += ["%" + arg("q") + "%"] * 2
        order = "ASC" if after else "DESC"   # after= catches up oldest-first; otherwise newest first
        rows, _ = run(f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY id {order} LIMIT ?", (*args, limit))
        items = [as_json(r) for r in rows]
        self.reply(200, {"items": items, "cursor": items[-1]["id"] if items else None})

    def feed(self, q):
        """Server-Sent Events: backlog after Last-Event-ID / ?after=, then live. Starts at "now" by default."""
        # ponytail: one thread per open feed; fine for dozens of subscribers, use an async server for thousands
        try:
            last = int(self.headers.get("Last-Event-ID") or (q.get("after") or [LATEST[0]])[0])
        except ValueError:
            return self.reply(400, {"error": "after must be a number"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(b": connected\n\n")
            while True:
                rows, _ = run("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 500", (last,))
                for r in rows:
                    self.wfile.write(f"id: {r['id']}\ndata: {json.dumps(as_json(r))}\n\n".encode())
                    last = r["id"]
                if len(rows) == 500:
                    continue
                with NEW:
                    moved = NEW.wait_for(lambda: LATEST[0] > last, timeout=15)
                if not moved:
                    self.wfile.write(b": keep-alive\n\n")   # also how we notice a subscriber that left
        except OSError:   # the subscriber went away
            pass

    # replies

    def reply(self, code, obj):
        self.send_body(code, json.dumps(obj).encode(), "application/json")

    def send_body(self, code, body, ctype, headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):   # a log line per request would slow down what we're measuring
        pass


# --- publishing with tailscale serve ---------------------------------------------------------------------------

def tailscale_cli():
    """The macOS app's own CLI first (it always matches the running Tailscale), then whatever is on PATH."""
    for c in ("/Applications/Tailscale.app/Contents/MacOS/Tailscale", shutil.which("tailscale")):
        if c and os.path.exists(c):
            return c
    sys.exit("Tailscale's command line tool wasn't found. Install Tailscale: https://tailscale.com/download")


def publish(port, https_port):
    """Runs `tailscale serve` for as long as this process runs. It un-publishes itself when we stop."""
    ts = tailscale_cli()
    out = subprocess.run([ts, "status", "--json"], capture_output=True, text=True)
    try:
        st = json.loads(out.stdout)
    except ValueError:
        sys.exit(f"`tailscale status` failed: {out.stderr.strip() or out.stdout.strip()}")
    if st.get("BackendState") != "Running":
        sys.exit("Tailscale isn't connected. Open the Tailscale app and log in (Linux: sudo tailscale up).")
    name = ((st.get("Self") or {}).get("DNSName") or "").rstrip(".")
    if not name:
        sys.exit("This machine has no MagicDNS name. Turn on MagicDNS: https://login.tailscale.com/admin/dns")
    proc = subprocess.Popen([ts, "serve", f"--https={https_port}", f"http://127.0.0.1:{port}"],
                            stdout=subprocess.DEVNULL)   # its errors and "enable HTTPS" link still show (stderr)
    return proc, f"https://{name}" + ("" if https_port == 443 else f":{https_port}"), st["Self"]["TailscaleIPs"][0]


def wait_until_live(url, proc, seconds=120):
    """Call our own published URL, so "live" means another tailnet device will get through too."""
    end, said = time.monotonic() + seconds, False
    while time.monotonic() < end:
        if proc.poll() is not None:
            sys.exit("tailscale serve stopped; its message is above. Is that HTTPS port already taken? "
                     "Check `tailscale serve status`, or pick another with --https-port.")
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=10):
                return True
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                print(f"Python can't verify certificates ({e.reason.verify_message}). On macOS with Python from "
                      "python.org, run 'Install Certificates.command' in its Applications folder.")
                return False
        except OSError:
            pass
        if not said:
            print("waiting for the HTTPS certificate (the first time can take up to a minute)...")
            said = True
        time.sleep(2)
    print(f"{url} isn't answering yet; check that HTTPS certificates are on: https://login.tailscale.com/admin/dns")
    return False


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))   # picks the outgoing interface; sends nothing
        return s.getsockname()[0]
    except OSError:
        return "<lan-ip>"
    finally:
        s.close()


def ensure_token():
    if os.environ.get("SERVICE_TOKEN"):
        return
    token = secrets.token_hex(32)
    old = ENV_FILE.read_text() if ENV_FILE.exists() else ""
    ENV_FILE.touch(0o600)          # create it owner-only before the token goes in
    os.chmod(ENV_FILE, 0o600)
    ENV_FILE.write_text(old + ("" if old.endswith("\n") or not old else "\n") + f"SERVICE_TOKEN={token}\n")
    os.environ["SERVICE_TOKEN"] = token
    print(f"created a write token: SERVICE_TOKEN in {ENV_FILE}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serve", action="store_true", help="publish to your tailnet with tailscale serve while running")
    ap.add_argument("--port", type=int, default=8080, help="local port (default 8080)")
    ap.add_argument("--https-port", type=int, default=8443, help="tailnet HTTPS port (default 8443)")
    ap.add_argument("--bind", default="127.0.0.1", help="leave this alone; 0.0.0.0 is for the no-Tailscale baseline only")
    ap.add_argument("--demo-data", type=int, default=0, metavar="N", help="add N sample events (for the benchmark)")
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # so `kill` also un-publishes (see finally)

    ensure_token()
    init_db()
    if a.demo_data:
        seed(a.demo_data)
    server = ThreadingHTTPServer((a.bind, a.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"listening on http://{a.bind}:{a.port}  ({LATEST[0]} events in {DB_PATH})")
    if a.bind != "127.0.0.1":
        print(f"WARNING: --bind {a.bind} makes this reachable WITHOUT Tailscale. Use it for the baseline run only.")

    proc = None
    try:
        if a.serve:
            proc, url, ts_ip = publish(a.port, a.https_port)
            if wait_until_live(url, proc):
                print(f"\nLIVE on your tailnet: {url}  (only your tailnet's devices can reach it)\n")
            print("From any device on your tailnet:")
            print(f"  curl {url}/whoami")
            print(f"  curl \"{url}/api/events?limit=5\"")
            print(f"  curl -N {url}/feed                (live feed; leave it open)")
            urls = (f"http://{lan_ip()}:{a.port} http://{ts_ip}:{a.port} " if a.bind != "127.0.0.1" else "") + url
            print(f"Benchmark it from another device:\n  python3 bench.py {urls}")
            print("\nCtrl-C stops the service and un-publishes it.")
        else:
            print(f"Not published. Add --serve, or publish it permanently:\n"
                  f"  tailscale serve --bg --https={a.https_port} http://127.0.0.1:{a.port}")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(10)


if __name__ == "__main__":
    main()
