# Tarpit Test Bed

A real, self-contained test bed for Tarpit — real processes, real HTTP
traffic between them, fake agents and fake credentials only. No real
IAM, no real secrets, no real data.

## What runs

- **fake-iam** — a fake ForgeRock-style OIDC server (internal only):
  `/.well-known/openid-configuration`, `/oauth2/authorize`,
  `/oauth2/token`, `/oauth2/userinfo`, and a decoy `/secrets/prod.env`.
  It only ever returns fake tokens and fake data.
- **gateway** — the Tarpit gate in front of the fake IAM, on port 8080.
  It fingerprints each attempt, scores it with the 3 pit checks
  (sequence, consistency, coordination — weighted 0.4 / 0.3 / 0.3),
  and logs every attempt to stdout and to `data/events.jsonl`.
  Monitor-only by default: it never blocks or removes automatically.
  It only flags and recommends remove (risk >= 70) — the operator decides.
- **attacker** — a FakePentestAgent swarm hitting the gateway:
  a legit control flow, naive brute-force, credential stuffing with
  a leaked fake credential, and a 5-agent coordinated swarm in lockstep.

## Launch in Codespaces — 3 steps

1. On the repo page, click **Code > Codespaces > Create codespace**.
2. In the Codespaces terminal, run:
   ```bash
   cd testbed && docker compose up --build
   ```
3. When Codespaces offers the forwarded port, open **port 8080**.
   That is the gateway status page.

## What to watch for

- The gateway status page (`/` on port 8080) shows live counts,
  fingerprints, and recent attempts. `/events` and `/fingerprints`
  return the same data as JSON.
- The coordinated swarm should cross risk 70 and trigger the alarm:
  `ALARM: risk >= 70 — recommend remove` in the gateway logs.
  Nothing is removed automatically — that is the operator's decision.
- The legit control flow should stay low-risk.
- Every attempt is also in `testbed/data/events.jsonl` — one JSON
  object per line, with fingerprint, scores, and risk.

## Notes

- Free Codespaces hours are limited. This is for testing and demoing,
  not a 24/7 live service — stop the codespace when you are done.
- Monitor-only: Tarpit flags and recommends. Removal is an explicit
  operator decision, logged with the fingerprint.
- All agents, credentials, tokens, and secrets in this test bed are fake.
