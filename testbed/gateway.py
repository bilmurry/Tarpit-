"""Tarpit gateway — real HTTP gate in front of the fake IAM.

Python stdlib only. Listens on 8080 (published), forwards requests
to fake-iam:8081, and scores every attempt with the 3 pit checks.

Fingerprint: SHA-256 of User-Agent + presented credential,
first 12 hex chars, prefixed fp_.
Sequence: endpoint order / repetition.
Consistency: User-Agent mismatch (bot / headless / FakePentestAgent)
  and fast, robotic timing.
Coordination: attempts in the last 60 seconds sharing a
  fingerprint / credential — the swarm tell.

Risk = 0.4 * sequence + 0.3 * consistency + 0.3 * coordination.
Recommend remove at risk >= 70.

Monitor-only by default: Tarpit never blocks or removes
automatically. It flags, logs, and recommends remove — the
operator decides Remove / Hold / Release.

Every attempt is logged to stdout and to /data/events.jsonl.
Status page: GET / — live counts.
JSON: GET /events, GET /fingerprints.
Everything else is proxied to the fake IAM.
"""
import hashlib
import json
import os
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = 8080
FAKE_IAM = "http://fake-iam:8081"
EVENTS_PATH = "/data/events.jsonl"

# In-memory state (per gateway process)
attempts = []          # list of event dicts, newest last
fingerprints = {}      # fp -> {"count": int, "first_seen": float, "last_seen": float, "risk": float, "recommend_remove": bool, "label": str}
start_time = time.time()


def fingerprint_for(user_agent, credential):
    raw = (user_agent or "") + "|" + (credential or "-")
    return "fp_" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def score_attempt(fp, user_agent, path, gap_seconds, now):
    """Return (sequence, consistency, coordination, risk)."""
    # Sequence: repeated attempts from this fingerprint, plus
    # skipping discovery (going straight to token) is suspicious.
    count = fingerprints.get(fp, {}).get("count", 0) + 1
    sequence = min(100, count * 20 + (25 if path.startswith("/oauth2/token") else 0))

    # Consistency: bot User-Agent, or robotic (very fast) timing.
    ua = (user_agent or "").lower()
    if "fakepentestagent" in ua or "bot" in ua or "headless" in ua:
        consistency = 80
    elif gap_seconds is not None and gap_seconds < 1.0:
        consistency = 60
    else:
        consistency = 10

    # Coordination: attempts sharing this fingerprint in the last 60s.
    recent = [a for a in attempts if a["fingerprint"] == fp and now - a["ts"] < 60]
    coordination = min(100, (len(recent) + 1) * 15)

    risk = 0.4 * sequence + 0.3 * consistency + 0.3 * coordination
    return sequence, consistency, coordination, risk


def log_event(event):
    attempts.append(event)
    fp = event["fingerprint"]
    entry = fingerprints.setdefault(fp, {
        "count": 0,
        "first_seen": event["ts"],
        "last_seen": event["ts"],
        "risk": 0,
        "recommend_remove": False,
        "label": event["label"],
    })
    entry["count"] += 1
    entry["last_seen"] = event["ts"]
    entry["risk"] = event["risk"]
    entry["recommend_remove"] = event["recommend_remove"]
    print("[gateway] %s %s fp=%s risk=%d seq=%d con=%d coord=%d %s" % (
        event["method"], event["path"], fp, event["risk"],
        event["sequence"], event["consistency"], event["coordination"],
        "ALARM recommend-remove" if event["recommend_remove"] else "flagged" if event["risk"] >= 40 else "ok",
    ), flush=True)
    if event["recommend_remove"]:
        print("[gateway] ALARM: risk >= 70 — recommend remove %s (operator decision only, nothing removed automatically)" % fp, flush=True)
    try:
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        with open(EVENTS_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        print("[gateway] could not write events file: %s" % e, flush=True)


class Gateway(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # we log attempts ourselves, in log_event()

    def _handle(self, method):
        # Status / monitoring endpoints are not IAM attempts: serve
        # them directly, without scoring or logging them.
        if method == "GET" and urlparse(self.path).path in ("/", "/events", "/fingerprints"):
            if self.path == "/":
                self._status_page()
            elif self.path == "/events":
                self._json(200, attempts[-100:])
            else:
                self._json(200, fingerprints)
            return

        now = time.time()
        user_agent = self.headers.get("User-Agent", "")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        # Presented credential: password / client secret in the body, if any.
        credential = ""
        try:
            text = body.decode(errors="ignore")
            for key in ("password=", "client_secret=", "credential="):
                if key in text:
                    credential = text.split(key, 1)[1].split("&")[0][:64]
                    break
        except Exception:
            credential = ""

        label = "FakePentestAgent" if "fakepentestagent" in user_agent.lower() else "client"
        fp = fingerprint_for(user_agent, credential)
        prev = fingerprints.get(fp, {})
        gap = (now - prev["last_seen"]) if prev else None
        sequence, consistency, coordination, risk = score_attempt(fp, user_agent, self.path, gap, now)

        event = {
            "ts": now,
            "method": method,
            "path": self.path,
            "label": label,
            "user_agent": user_agent,
            "fingerprint": fp,
            "sequence": sequence,
            "consistency": consistency,
            "coordination": coordination,
            "risk": int(risk),
            "recommend_remove": risk >= 70,
            "action": "flagged — monitor only, no removal",
        }
        log_event(event)

        if self.path == "/" and method == "GET":
            self._status_page()
            return
        if self.path == "/events" and method == "GET":
            self._json(200, attempts[-100:])
            return
        if self.path == "/fingerprints" and method == "GET":
            self._json(200, fingerprints)
            return

        # Proxy everything else to the fake IAM (Monitor-only: forward,
        # never block — the fake IAM only ever returns fake data).
        self._proxy(method, body)

    def _json(self, status, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _status_page(self):
        flagged = sum(1 for a in attempts if a["risk"] >= 40)
        alarms = sum(1 for a in attempts if a["recommend_remove"])
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>" % (
                fp, e["label"], e["count"], int(e["risk"]),
                "RECOMMEND REMOVE" if e["recommend_remove"] else "flagged",
            )
            for fp, e in sorted(fingerprints.items(), key=lambda kv: -kv[1]["risk"])
        )
        recent = "".join(
            "<li>%s %s — %s risk %d</li>" % (
                a["method"], a["path"], a["fingerprint"], a["risk"],
            )
            for a in attempts[-20:]
        )
        html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Tarpit Gateway — Monitor-only</title></head><body>
<h1>Tarpit Gateway — Monitor-only</h1>
<p>Gate in front of the fake IAM. Nothing is blocked or removed automatically — flagged attempts are logged and a remove is only recommended. The operator decides.</p>
<p>Checked: %d &middot; Flagged: %d &middot; Alarms (risk &gt;= 70): %d &middot; Fingerprints: %d &middot; Uptime: %ds</p>
<h2>Fingerprints</h2>
<table border="1"><tr><th>Fingerprint</th><th>Label</th><th>Attempts</th><th>Risk</th><th>Status</th></tr>%s</table>
<h2>Recent attempts</h2><ul>%s</ul>
<p><a href="/events">/events</a> &middot; <a href="/fingerprints">/fingerprints</a> &middot; Events log: /data/events.jsonl</p>
</body></html>""" % (len(attempts), flagged, alarms, len(fingerprints),
                   int(time.time() - start_time), rows, recent)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, method, body):
        url = FAKE_IAM + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        req = urllib.request.Request(url, data=body if method in ("POST", "PUT", "PATCH") else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("connection", "transfer-encoding", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._json(502, {"error": "fake_iam_unreachable", "detail": str(e)})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")


if __name__ == "__main__":
    print("[gateway] Tarpit gateway listening on 0.0.0.0:%d, forwarding to %s (Monitor-only)" % (PORT, FAKE_IAM), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Gateway).serve_forever()
