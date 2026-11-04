// Tarpit — Passive Agent Monitor
// Modelled on Ghost Job Detector, but for IAM instead of job sites.
// Monitor-only by default. No auto-block, no auto-remove.
// The user decides: Recommend remove -> they click Remove in the popup.
// Alarm: badge + Chrome notification + stored intrusion, on attempted intrusion.

const IAM_PATTERNS = [
  { host: "forgerock", pathIncludes: "/" },
  { host: "oauth", pathIncludes: "/" },
  { host: "", pathIncludes: "/oauth2/token" },
  { host: "", pathIncludes: "/oauth2/authorize" },
  { host: "", pathIncludes: "/oauth/authorize" },
  { host: "", pathIncludes: "/oauth/token" },
  { host: "", pathIncludes: "/authorize" },
  { host: "", pathIncludes: "/login" },
  { host: "", pathIncludes: "/auth" },
  { host: "", pathIncludes: "/am/oauth2" },
  { host: "", pathIncludes: "/am/json" },
  { host: "", pathIncludes: "/openid" },
  { host: "", pathIncludes: "/.well-known/openid-configuration" },
];

const RECOMMEND_REMOVE_THRESHOLD = 70;
const ALARM_THRESHOLD = 70;

function isIamUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    for (const p of IAM_PATTERNS) {
      const hostOk = !p.host || host.includes(p.host);
      if (hostOk && path.includes(p.pathIncludes)) return true;
    }
  } catch {}
  return false;
}

// Simple, local fingerprint — no server needed, no tokens spent.
// Hash of User-Agent + host + first path. Stable enough to spot
// the same agent across tabs / networks, without collecting PII.
async function fingerprintFor(tab) {
  const raw = `${tab.url || ""}|${navigator.userAgent || "unknown"}`;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return "fp_" + hex.slice(0, 12);
}

// The 3 pit checks, scored locally (0-100 each, like the Tarpit console).
// sequence: rapid, repeated token / login attempts in the same order
// consistency: timing / User-Agent / flow mismatches
// coordination: many attempts in a short window, same fingerprint
function scoreAttempt(signals) {
  const sequence = Math.min(100, (signals.attemptCount || 0) * 20 + (signals.repeatedPath ? 25 : 0));
  const consistency = signals.uaMismatch ? 80 : signals.fastTiming ? 60 : 10;
  const coordination = Math.min(100, (signals.attemptsIn60s || 0) * 15);
  const risk = Math.round(sequence * 0.4 + consistency * 0.3 + coordination * 0.3);
  return { sequence, consistency, coordination, risk, recommendRemove: risk >= RECOMMEND_REMOVE_THRESHOLD };
}

function updateBadge(tabId, risk) {
  if (risk >= ALARM_THRESHOLD) {
    chrome.action.setBadgeText({ text: "!", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#DC2626", tabId });
    chrome.action.setBadgeTextColor({ color: "#FFFFFF", tabId });
  } else if (risk > 0) {
    chrome.action.setBadgeText({ text: "•", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId });
    chrome.action.setBadgeTextColor({ color: "#FFFFFF", tabId });
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

async function raiseAlarm(intrusion) {
  // Alarm system: badge + notification + stored record. No auto-action.
  try {
    await chrome.notifications.create(`tarpit-${intrusion.id}`, {
      type: "basic",
      iconUrl: "icon.png",
      title: "Tarpit alarm: attempted intrusion",
      message: `${intrusion.label} — risk ${intrusion.risk}/100. Fingerprint ${intrusion.fingerprint}. Open Tarpit to decide: Remove, Hold, or Release.`,
      priority: 2,
    });
  } catch (e) {
    console.warn("Tarpit notification failed:", e);
  }
  const { intrusions = [] } = await chrome.storage.local.get(["intrusions"]);
  intrusions.unshift(intrusion);
  await chrome.storage.local.set({ intrusions: intrusions.slice(0, 50) });
}

async function recordAttempt(tabId, signals) {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab || !tab.url) return null;
  const fingerprint = await fingerprintFor(tab);
  const scored = scoreAttempt(signals);
  const intrusion = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    fingerprint,
    url: tab.url,
    label: signals.label || "IAM login attempt",
    origin: new URL(tab.url).hostname,
    entryEndpoint: new URL(tab.url).pathname,
    risk: scored.risk,
    sequence: scored.sequence,
    consistency: scored.consistency,
    coordination: scored.coordination,
    recommendRemove: scored.recommendRemove,
    status: "flagged",
    decision: "awaiting your decision",
    firstSeen: new Date().toISOString(),
    trace: [
      `Origin: ${new URL(tab.url).hostname}`,
      `Entry: ${new URL(tab.url).pathname}`,
      `Attempts in window: ${signals.attemptsIn60s || 1}`,
      `Intended target: resource behind IAM`,
      `Outcome in Monitor mode: flagged only — no trap, no removal`,
    ],
  };
  updateBadge(tabId, scored.risk);
  if (scored.risk >= ALARM_THRESHOLD) {
    await raiseAlarm(intrusion);
  }
  return intrusion;
}

async function ensureContentScript(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "PING" });
    return true;
  } catch {
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
      return true;
    } catch (err) {
      console.error("Tarpit: failed to inject content script:", err);
      return false;
    }
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(["mode"], (r) => {
    if (!r.mode) chrome.storage.sync.set({ mode: "monitor" });
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && isIamUrl(tab.url)) {
    ensureContentScript(tabId).catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "IAM_ATTEMPT") {
    const tabId = sender.tab ? sender.tab.id : message.tabId;
    if (!tabId) return false;
    recordAttempt(tabId, message.signals || {}).then((intrusion) => sendResponse({ ok: true, intrusion }));
    return true;
  }
  if (message.type === "REMOVE_INTRUSION") {
    // Operator decision only — this is the only path to "removed".
    (async () => {
      const { intrusions = [] } = await chrome.storage.local.get(["intrusions"]);
      const next = intrusions.map((i) =>
        i.id === message.id ? { ...i, status: "removed", decision: `removed by you at ${new Date().toISOString()}` } : i
      );
      await chrome.storage.local.set({ intrusions: next });
      sendResponse({ ok: true });
    })();
    return true;
  }
  if (message.type === "GET_INTRUSIONS") {
    chrome.storage.local.get(["intrusions"], (r) => sendResponse({ intrusions: r.intrusions || [] }));
    return true;
  }
});
