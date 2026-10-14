#!/usr/bin/env python3
"""python3 check.py: runs the service and a fake vendor API on loopback and checks every route, then runs the bench.
Touches nothing outside a temp folder; no Tailscale needed."""
import http.client, json, os, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Vendor(BaseHTTPRequestHandler):
    """Stands in for a third-party API: records what reached it."""
    hits = []

    def do_GET(self):
        Vendor.hits.append((self.path, self.headers.get("X-API-Key"), self.headers.get("Authorization")))
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/leak")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_port


vendor = start(Vendor)
TOKEN = "t" * 64
os.environ.update(DB_PATH=os.path.join(tempfile.mkdtemp(), "events.db"), SERVICE_TOKEN=TOKEN, WRITERS="me@example.com",
                  UPSTREAM_URL=f"http://127.0.0.1:{vendor}/v1", UPSTREAM_HEADER="X-API-Key", UPSTREAM_KEY="vendor-secret")
import bench, service   # noqa: E402  (reads the settings above)

service.init_db()
port = start(service.Handler)
URL = f"http://127.0.0.1:{port}"
AUTH = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"}


def call(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, json.dumps(body) if isinstance(body, dict) else body, headers or {})
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, r.headers, json.loads(raw)
    except ValueError:
        return r.status, r.headers, raw


# health and identity: Tailscale headers are trusted from loopback (that's where tailscale serve connects from)
assert call("GET", "/healthz")[2] == {"ok": True}
who = call("GET", "/whoami", headers={"Tailscale-User-Login": "me@example.com"})[2]
assert who["login"] == "me@example.com" and who["via_tailscale_serve"] and who["can_write"], who
assert call("GET", "/whoami")[2]["can_write"] is False

# webhook in: token or WRITERS, validated body
assert call("POST", "/api/events", {"type": "x"})[0] == 401
assert call("POST", "/api/events", {"type": "x"}, {"Authorization": "Bearer wrong"})[0] == 401
assert call("POST", "/api/events", {"message": "no type"}, AUTH)[0] == 400
assert call("POST", "/api/events", "not json", AUTH)[0] == 400
assert call("POST", "/api/events", "x" * (service.MAX_BODY + 1), AUTH)[0] == 413
s, _, first = call("POST", "/api/events", {"type": "backup.finished", "source": "nas", "message": "ok", "data": {"gb": 12}}, AUTH)
assert s == 201, first
ME = {"Tailscale-User-Login": "ME@example.com", "Content-Type": "application/json"}
s, _, second = call("POST", "/api/events", {"type": "job.failed"}, ME)
assert s == 201, second   # WRITERS match is case-insensitive
# a cross-site page can make the browser post text/plain (CSRF) or rebind its own name to 127.0.0.1
assert call("POST", "/api/events", {"type": "csrf"}, {**ME, "Content-Type": "text/plain"})[0] == 415
assert call("POST", "/api/events", {"type": "rebind"}, {**ME, "Host": "evil.example:8080"})[0] == 421
assert call("GET", "/healthz", headers={"Host": "box.tail1234.ts.net:8443"})[0] == 200

# REST API
ev = call("GET", f"/api/events/{first['id']}")[2]
assert ev["source"] == "nas" and ev["data"] == {"gb": 12} and ev["at"].endswith("Z"), ev
assert call("GET", "/api/events/999999")[0] == 404 and call("GET", "/api/events/abc")[0] == 404
assert call("GET", f"/api/events/{second['id']}")[2]["source"] == "ME@example.com"   # defaults to the caller's login
service.seed(30)
page = call("GET", "/api/events?limit=10")[2]
ids = [e["id"] for e in page["items"]]
assert len(ids) == 10 and ids == sorted(ids, reverse=True) and page["cursor"] == ids[-1]   # newest first
older = call("GET", f"/api/events?limit=10&before={page['cursor']}")[2]["items"]
assert older[0]["id"] == page["cursor"] - 1
newer = call("GET", f"/api/events?after={first['id']}&limit=500")[2]["items"]
assert [e["id"] for e in newer] == list(range(first["id"] + 1, service.LATEST[0] + 1))   # catch-up is oldest first
assert all(e["type"] == "job.failed" for e in call("GET", "/api/events?type=job.failed")[2]["items"])
assert call("GET", "/api/events?q=gb")[2]["items"][0]["id"] == first["id"]
assert call("GET", "/api/events?limit=x")[0] == 400

# export: every event, and it notices new ones
lines = call("GET", "/api/export")[2].splitlines()
assert len(lines) == service.LATEST[0] and json.loads(lines[0])["id"] == first["id"], len(lines)
call("POST", "/api/events", {"type": "after.export"}, AUTH)
assert json.loads(call("GET", "/api/export")[2].splitlines()[-1])["type"] == "after.export"

# live feed: resume from Last-Event-ID, then live delivery
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.request("GET", "/feed", headers={"Last-Event-ID": str(service.LATEST[0] - 1)})
r = c.getresponse()
assert r.status == 200 and r.headers["Content-Type"] == "text/event-stream"
data = lambda: json.loads(next(ln for ln in iter(r.readline, b"") if ln.startswith(b"data:"))[5:])
assert data()["type"] == "after.export"   # the backlog after Last-Event-ID
call("POST", "/api/events", {"type": "live"}, AUTH)
assert data()["type"] == "live"
c.close()

# vendor gateway: the key is added here, the caller's own credentials never go upstream, redirects aren't followed
s, h, body = call("GET", "/upstream/lookup?ip=203.0.113.9", headers={"Authorization": "Bearer caller-token"})
assert s == 200 and body == {"path": "/v1/lookup?ip=203.0.113.9"} and h["X-Cache"] == "miss", (s, body)
assert Vendor.hits[-1] == ("/v1/lookup?ip=203.0.113.9", "vendor-secret", None), Vendor.hits[-1]
s, h, _ = call("GET", "/upstream/lookup?ip=203.0.113.9")
assert h["X-Cache"] == "hit" and len(Vendor.hits) == 1 and h["Content-Security-Policy"].startswith("sandbox")   # cached
assert call("GET", "/upstream/redirect")[0] == 302 and not any(p == "/leak" for p, _, _ in Vendor.hits)
assert call("GET", "/upstream/../admin")[0] in (400, 404) and call("GET", "/upstream/%2e%2e/admin")[0] == 400
service.UPSTREAM_URL = ""
assert call("GET", "/upstream/x")[0] == 503

# unknown routes
assert call("GET", "/nope")[0] == 404 and call("POST", "/nope", {})[0] == 404

# the bench, end to end against the running service
m = bench.measure(URL, n=50, feed_n=20, token=TOKEN)
assert m["api"][0] <= m["api"][1] <= m["api"][2] and m["feed"] and not m["note"] and m["mbps"] > 0, m
m = bench.measure(URL, n=5, feed_n=3, token="wrong")
assert "no write access" in m["note"], m

print("ok: every route, the feed, the gateway and the bench work")
