"use strict";
const $ = (id) => document.getElementById(id);
const fields = [
  ["received", "Queries received"], ["blocked", "Blocked queries"],
  ["cache_hits", "Cache hits"], ["forwarded", "Forwarded queries"],
  ["upstream_errors", "Upstream errors"], ["cache_bytes", "Cache bytes"],
];
const labels = {invalid:"Invalid queries",overloaded:"Overloaded queries",denied:"Denied clients",send_errors:"Send errors",inflight:"In flight",peak_inflight:"Peak in flight",cache_misses:"Cache misses",cache_entries:"Cache entries",cache_evictions:"Cache evictions"};
const numbers = new Intl.NumberFormat();
let bearer = "", timer, controller, generation = 0;
let policyController, policyGeneration = 0;
function setState(text) { $("connection").textContent = text; }
function disconnect(message = "Not connected") {
  cancelPolicy(); $("hostname").value = ""; $("policy-result").textContent = "";
  generation++; bearer = ""; clearTimeout(timer); controller?.abort();
  $("token").value = ""; $("login").hidden = false; $("overview").hidden = true;
  $("metrics").replaceChildren(); $("details").replaceChildren(); setState(message);
}
function render(data) {
  if (data.schema_version !== 1 || !data.dns || !data.policy) throw new Error("schema");
  const cards = fields.map(([key, label]) => {
    const card = document.createElement("article"); card.className = "metric";
    const title = document.createElement("h2"); title.textContent = label;
    const value = document.createElement("strong"); value.textContent = numbers.format(data.dns[key]);
    card.append(title, value); return card;
  });
  $("metrics").replaceChildren(...cards);
  const rows = Object.entries({...Object.fromEntries(fields), ...labels}).flatMap(([key, label]) => {
    const term = document.createElement("dt"), value = document.createElement("dd");
    term.textContent = label; value.textContent = numbers.format(data.dns[key]); return [term, value];
  });
  $("details").replaceChildren(...rows);
  $("service-meta").textContent = `${numbers.format(data.policy.rules)} ${data.policy.rules === 1 ? "rule" : "rules"} · ${numbers.format(data.policy.bytes)} index bytes · ${numbers.format(data.uptime_seconds)}s uptime`;
  $("policy-mode").textContent = data.policy.rules === 0 ? "No filtering rules selected." : data.policy.enabled_categories === 0 ? "All filtering categories are disabled." : "Checks use this service’s active categories.";
  $("version").textContent = data.version;
  $("login").hidden = true; $("overview").hidden = false;
  setState(`Connected · Updated ${new Date().toLocaleTimeString()}`);
}
async function poll() {
  clearTimeout(timer);
  if (!bearer || document.hidden) return;
  const current = ++generation;
  controller?.abort(); controller = new AbortController();
  const active = controller;
  const timeout = setTimeout(() => active.abort(), 4000);
  try {
    const response = await fetch("/api/v1/status", {headers:{Authorization:`Bearer ${bearer}`},cache:"no-store",credentials:"omit",signal:active.signal});
    if (current !== generation) return;
    if (response.status === 401) { disconnect("Token rejected. Check the token for this service."); return; }
    if (!response.ok) throw new Error("unavailable");
    const data = await response.json();
    if (current === generation) render(data);
  } catch (_) {
    if (current === generation) setState("Service unavailable · Displayed values may be stale. Retrying…");
  } finally {
    clearTimeout(timeout);
    if (current === generation && bearer && !document.hidden) timer = setTimeout(poll, 2000);
  }
}
$("connect").addEventListener("submit", (event) => {
  event.preventDefault(); bearer = $("token").value.trim(); $("token").value = "";
  setState("Connecting…"); poll();
});
$("disconnect").addEventListener("click", () => disconnect());
document.addEventListener("visibilitychange", () => {
  if (document.hidden) { if (policyController) { cancelPolicy(); $("policy-result").textContent = "Check cancelled while this tab was hidden."; } generation++; clearTimeout(timer); controller?.abort(); if (bearer) setState("Paused while this tab is hidden"); }
  else poll();
});
window.addEventListener("pagehide", () => disconnect());

const categoryNames = [[1,"Ads"],[2,"Adult"],[4,"Malware"],[8,"Tracking"],[16,"Phishing"],[32,"Gambling"],[64,"Social"]];
function categories(mask) { return categoryNames.filter(([bit]) => (mask & bit) !== 0).map(([,name]) => name).join(", "); }
function cancelPolicy() {
  policyGeneration++; policyController?.abort(); policyController = undefined;
  $("policy-submit").disabled = false;
}
$("policy-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if (!bearer || document.hidden) return;
  cancelPolicy(); const current = policyGeneration;
  const active = new AbortController(); policyController = active;
  const timeout = setTimeout(() => active.abort(), 4000);
  $("policy-submit").disabled = true; $("policy-result").textContent = "Checking…";
  try {
    const response = await fetch("/api/v1/policy/check", {
      method:"POST", headers:{Authorization:`Bearer ${bearer}`,"Content-Type":"application/json"},
      body:JSON.stringify({domain:$("hostname").value.trim()}),
      cache:"no-store", credentials:"omit", signal:active.signal,
    });
    if (current !== policyGeneration) return;
    if (response.status === 401) { disconnect("Token rejected. Check the token for this service."); return; }
    if (response.status === 400) { $("policy-result").textContent = "Enter a valid ASCII hostname. Use an IDNA A-label for international names."; return; }
    if (!response.ok) throw new Error("unavailable");
    const result = await response.json();
    if (current !== policyGeneration) return;
    if (result.schema_version !== 1 || typeof result.blocked !== "boolean") throw new Error("schema");
    let text = `${result.blocked ? "Blocked" : "Allowed"} · ${result.domain}`;
    if (result.blocked_categories) text += ` · ${categories(result.blocked_categories)}`;
    if (result.allowed_categories) text += ` · Allow exception: ${categories(result.allowed_categories)}`;
    if (result.enforced_categories) text += ` · Enforced: ${categories(result.enforced_categories)}`;
    $("policy-result").textContent = text;
  } catch (_) {
    if (current === policyGeneration) $("policy-result").textContent = "Check unavailable. Try again when the service is reachable.";
  } finally {
    clearTimeout(timeout);
    if (current === policyGeneration) { policyController = undefined; $("policy-submit").disabled = false; }
  }
});
