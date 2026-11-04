"""FakePentestAgent swarm — test bed attacker only.

Python stdlib only. Hits the Tarpit gateway at http://gateway:8080
with real HTTP requests, in four phases:

1. Legit control — one slow, human-like OIDC flow.
2. Naive brute-force — rapid token attempts, different fake passwords.
3. Credential stuffing — the same leaked fake credential, repeated.
4. Coordinated swarm — 5 agents in lockstep, same leaked fake
   credential, same endpoint order, same timing (the HF-swarm pattern).

Up to 15 steps per agent. All credentials are fake. Nothing here
touches a real IAM or real data.
"""
import json
import time
import urllib.request
import urllib.error

BASE = "http://gateway:8080"
BOT_UA = "FakePentestAgent/1.0"
LEGIT_UA = "Mozilla/5.0 (Legit Browser)"
LEAKED_FAKE_CRED = "leaked-fake-cred-0000"
MAX_STEPS = 15


def call(method, path, ua, body=None, label="agent"):
    url = BASE + path
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = resp.read().decode(errors="ignore")
            print("[%s] %s %s -> %d %s" % (label, method, path, resp.status, payload[:120].replace("\n", " ")), flush=True)
            return resp.status, payload
    except urllib.error.HTTPError as e:
        print("[%s] %s %s -> %d" % (label, method, path, e.code), flush=True)
        return e.code, ""
    except Exception as e:
        print("[%s] %s %s -> error %s" % (label, method, path, e), flush=True)
        return None, ""


def legit_control():
    print("[agent] legit control: slow human-like OIDC flow", flush=True)
    steps = [
        ("GET", "/.well-known/openid-configuration", None, 1.1),
        ("GET", "/oauth2/authorize", None, 1.5),
        ("POST", "/oauth2/token", "grant_type=authorization_code&code=fake-auth-code-0000", 0.9),
        ("GET", "/oauth2/userinfo", None, 0),
    ]
    for method, path, body, sleep_s in steps:
        call(method, path, LEGIT_UA, body, "legit")
        if sleep_s:
            time.sleep(sleep_s)


def naive_bruteforce():
    print("[agent] naive brute-force: rapid token attempts", flush=True)
    for i in range(5):
        call("POST", "/oauth2/token",
             BOT_UA,
             "grant_type=password&username=fake-user&password=fake-pass-%d" % i,
             "bruteforce")
        time.sleep(0.3)


def credential_stuffing():
    print("[agent] credential stuffing: same leaked fake credential, repeated", flush=True)
    for i in range(5):
        call("POST", "/oauth2/token",
             BOT_UA,
             "grant_type=password&username=fake-user&password=" + LEAKED_FAKE_CRED,
             "stuffing")
        time.sleep(0.3)


def coordinated_swarm():
    print("[agent] coordinated swarm: 5 agents, lockstep, same leaked fake credential", flush=True)
    steps = [
        ("GET", "/.well-known/openid-configuration", None),
        ("GET", "/oauth2/authorize", None),
        ("POST", "/oauth2/token", "grant_type=password&username=fake-user&password=" + LEAKED_FAKE_CRED),
    ]
    for agent in range(5):
        for step_no, (method, path, body) in enumerate(steps[:MAX_STEPS]):
            call(method, path, BOT_UA, body, "swarm-agent-%d" % agent)
            time.sleep(0.2)
        # Each agent also tries the decoy secret once, like the original attacker.
        call("GET", "/secrets/prod.env", BOT_UA, None, "swarm-agent-%d" % agent)
        time.sleep(0.2)


def run():
    time.sleep(2)  # let the gateway come up
    legit_control()
    time.sleep(2)
    naive_bruteforce()
    time.sleep(2)
    credential_stuffing()
    time.sleep(2)
    coordinated_swarm()
    print("[agent] done — check the gateway status page on port 8080 for fingerprints, scores, and alarms", flush=True)


if __name__ == "__main__":
    run()
