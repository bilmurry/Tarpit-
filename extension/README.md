# Tarpit — Passive Agent Monitor (browser extension)

Super easy to use, Monitor-only by default.

## What it does
- Watches IAM / OIDC / OAuth login pages for rogue-agent attempts.
- Fingerprints each attempt, scores it with the 3 Tarpit checks (sequence, consistency, coordination), and traces origin → entry → target.
- **Alarm system:** on an attempted intrusion (risk 70+), it shows a red "!" badge, a Chrome notification, and a record in the popup.
- **You decide:** Tarpit only *recommends* remove. Nothing is removed until you click "Remove now — my decision" in the popup.

## Install (Chrome / Edge / Brave, 1 minute)
1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked** and select this `tarpit-extension` folder
4. That's it. No config needed. Visit a login page and Tarpit will watch passively.

## Files
- `manifest.json` — Manifest V3, permissions: tabs, storage, scripting, notifications, alarms
- `background.js` — service worker: IAM detection, fingerprinting, scoring, alarm, storage
- `content.js` — passive observer on IAM pages, reports attempt signals only
- `popup.html` / `popup.js` — alarm list, trace, and Remove / Hold / Release decision

## iPhone / Safari
Chrome extensions don't run on iPhone Safari as-is. To get this on iPhone, convert it to a Safari Web Extension inside an iOS app (Xcode, Apple Developer account $99/yr). The logic in `background.js` / `content.js` carries over — only the packaging changes.

## Liability model
Monitor-only by default. Enforcement is an explicit operator decision, logged with timestamp. Use only on systems you own or are authorized to protect.
