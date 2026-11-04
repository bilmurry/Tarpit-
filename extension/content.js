// Tarpit content script — passive observer only.
// Watches IAM / login pages for rapid, repeated attempts and reports
// signals to background.js. It never blocks, redirects, or changes the page.

let attemptCount = 0;
let lastAttemptAt = 0;
const attemptsInWindow = [];

function isIamPage() {
  const p = window.location.pathname.toLowerCase();
  return ["/oauth2/", "/oauth/", "/authorize", "/token", "/login", "/auth", "/am/"].some((s) => p.includes(s));
}

function noteAttempt(label) {
  const now = Date.now();
  attemptCount += 1;
  attemptsInWindow.push(now);
  while (attemptsInWindow.length && now - attemptsInWindow[0] > 60000) attemptsInWindow.shift();
  const fastTiming = lastAttemptAt ? now - lastAttemptAt < 1000 : false;
  lastAttemptAt = now;
  chrome.runtime.sendMessage({
    type: "IAM_ATTEMPT",
    signals: {
      label,
      attemptCount,
      attemptsIn60s: attemptsInWindow.length,
      repeatedPath: attemptCount > 1,
      fastTiming,
      uaMismatch: /bot|headless|FakePentestAgent/i.test(navigator.userAgent),
    },
  }).catch(() => {});
}

if (isIamPage()) {
  // A login page load itself is one observation.
  noteAttempt("IAM page loaded");
  // Rapid form submits / token fetches are the sequence signal.
  document.addEventListener("submit", () => noteAttempt("Login form submitted"), true);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "PING") sendResponse({ ok: true, isIamPage: isIamPage() });
  if (message.type === "CHECK_IAM_PAGE") sendResponse({ isIamPage: isIamPage() });
});
