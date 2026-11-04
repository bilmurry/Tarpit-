chrome.runtime.sendMessage({ type: "GET_INTRUSIONS" }, (res) => {
  const list = document.getElementById("list");
  const items = res?.intrusions || [];
  if (!items.length) return;
  list.innerHTML = "";
  for (const i of items) {
    const div = document.createElement("div");
    div.className = "card";
    div.innerHTML = `
      <div class="${i.risk >= 70 ? "alarm" : ""}">🚨 Attempted intrusion — risk <span class="risk">${i.risk}/100</span></div>
      <div><strong>${i.label}</strong></div>
      <div class="muted">${i.origin} — ${i.entryEndpoint}</div>
      <div class="muted">Fingerprint: ${i.fingerprint}</div>
      <div class="muted">Sequence ${i.sequence} · Consistency ${i.consistency} · Coordination ${i.coordination}</div>
      <div class="muted">Status: ${i.status} — ${i.decision}</div>
      <div class="muted">${i.trace ? i.trace.join(" → ") : ""}</div>
      ${i.status !== "removed" && i.recommendRemove ? `<button data-id="${i.id}">Remove now — my decision</button>` : ""}
    `;
    const btn = div.querySelector("button");
    if (btn) {
      btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "REMOVE_INTRUSION", id: i.id }, () => window.location.reload());
      });
    }
    list.appendChild(div);
  }
});
