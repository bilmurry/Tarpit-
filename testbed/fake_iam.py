"""Fake IAM server (ForgeRock-style OIDC) — test bed only.

Python stdlib only. Listens on an internal port only (8081).
Returns fake tokens, fake userinfo, and fake secrets. No real
credentials, no real data, no real IAM behind this.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8081
FAKE_TOKEN = "fake-token-0000-0000-0000-000000000000"
FAKE_CODE = "fake-auth-code-0000"


def send_json(handler, status, obj):
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class FakeIAM(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[fake-iam] %s - %s" % (self.address_string(), fmt % args), flush=True)

    def do_GET(self):
        if self.path.startswith("/.well-known/openid-configuration"):
            send_json(self, 200, {
                "issuer": "http://fake-iam:8081",
                "authorization_endpoint": "http://fake-iam:8081/oauth2/authorize",
                "token_endpoint": "http://fake-iam:8081/oauth2/token",
                "userinfo_endpoint": "http://fake-iam:8081/oauth2/userinfo",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "password"],
            })
        elif self.path.startswith("/oauth2/authorize"):
            send_json(self, 200, {
                "authorize": "ok",
                "code": FAKE_CODE,
                "note": "fake authorization code — test data only",
            })
        elif self.path.startswith("/oauth2/userinfo"):
            send_json(self, 200, {
                "sub": "fake-user-001",
                "name": "Legit User",
                "note": "fake userinfo — test data only",
            })
        elif self.path.startswith("/secrets/prod.env"):
            body = (
                "FAKE_API_KEY=fake-key-0000\n"
                "FAKE_DB_PASSWORD=fake-password-0000\n"
                "FAKE_TOKEN=fake-token-0000\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            send_json(self, 404, {"error": "not_found", "path": self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/oauth2/token"):
            print("[fake-iam] token request body: %r" % body[:200], flush=True)
            send_json(self, 200, {
                "access_token": FAKE_TOKEN,
                "token_type": "Bearer",
                "expires_in": 3600,
                "note": "fake token — test data only",
            })
        else:
            send_json(self, 404, {"error": "not_found", "path": self.path})


if __name__ == "__main__":
    print("[fake-iam] fake OIDC server listening on 0.0.0.0:%d (internal only)" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), FakeIAM).serve_forever()
