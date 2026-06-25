/* ============================================================
   FraudDroid v2.0 — Frontend Logic
   ============================================================ */

const $ = id => document.getElementById(id);
let currentReport = null;

// ---------------------------------------------------------------------------
// Upload handling
// ---------------------------------------------------------------------------

const dropZone  = $("dropZone");
const fileInput = $("fileInput");

dropZone.addEventListener("click", e => {
  if (!e.target.classList.contains("file-label")) fileInput.click();
});
fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) startAnalysis(fileInput.files[0]);
});
dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", e => {
  e.preventDefault(); dropZone.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith(".apk")) startAnalysis(file);
  else alert("Only .apk files are accepted.");
});
$("rescanBtn").addEventListener("click", resetUI);

window.addEventListener("load", () => {
  $("reportSection").classList.add("hidden");
  $("progressSection").classList.add("hidden");
  $("uploadSection").classList.remove("hidden");
});

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

const STEPS = [
  "Unpacking APK archive...",
  "Parsing AndroidManifest.xml...",
  "Extracting permission list...",
  "Running permission cluster analysis...",
  "Scanning for malware behavior patterns...",
  "Extracting strings from .dex files...",
  "Scanning for hardcoded IOCs...",
  "Running fraud signature matching...",
  "Resolving DNS records for C2 domains...",
  "Querying WHOIS intelligence...",
  "Analyzing IP infrastructure...",
  "Computing composite risk score...",
  "Building investigation report...",
];

let stepTimer = null, stepIdx = 0;

function startProgressAnimation() {
  stepIdx = 0;
  $("progressLabel").textContent = STEPS[0];
  $("progressBar").style.width = "5%";
  stepTimer = setInterval(() => {
    if (stepIdx < STEPS.length - 1) {
      stepIdx++;
      const pct = Math.min(92, 5 + (stepIdx / (STEPS.length - 1)) * 87);
      $("progressBar").style.width = pct + "%";
      $("progressLabel").textContent = STEPS[stepIdx];
    }
  }, 2500);
}

function finishProgress() {
  clearInterval(stepTimer);
  $("progressBar").style.width = "100%";
  $("progressLabel").textContent = "Done!";
}

// ---------------------------------------------------------------------------
// Main analysis flow
// ---------------------------------------------------------------------------

async function startAnalysis(file) {
  $("uploadSection").classList.add("hidden");
  $("reportSection").classList.add("hidden");
  $("progressSection").classList.remove("hidden");
  startProgressAnimation();

  const formData = new FormData();
  formData.append("apk", file);

  try {
    const res  = await fetch("/analyze", { method: "POST", body: formData });
    const data = await res.json();
    finishProgress();

    if (res.status === 504 || (data.error && data.error.includes("timed out"))) {
      alert("This APK took too long to analyze on the server.\n\nTip: Run FraudDroid locally for large APKs.");
      resetUI(); return;
    }
    if (data.error) { alert("Analysis error: " + data.error); resetUI(); return; }
    if (typeof data.total_score === "undefined" || data.total_score === null) {
      alert("Server returned an incomplete report. Please try again.");
      resetUI(); return;
    }

    currentReport = data;
    setTimeout(() => renderReport(data), 400);
  } catch (err) {
    finishProgress();
    alert("Request failed: " + err.message);
    resetUI();
  }
}

function resetUI() {
  clearInterval(stepTimer);
  $("progressSection").classList.add("hidden");
  $("reportSection").classList.add("hidden");
  $("uploadSection").classList.remove("hidden");
  fileInput.value = "";
  currentReport = null;
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

function renderReport(r) {
  if (!r || typeof r.total_score !== "number" || !r.verdict || !r.manifest) {
    alert("Report data is incomplete. Please re-upload the APK.");
    resetUI(); return;
  }
  $("progressSection").classList.add("hidden");
  $("reportSection").classList.remove("hidden");
  renderVerdict(r);
  renderMeta(r);
  renderSummary(r);
  renderPermissions(r);
  renderStrings(r);
  renderIntelligence(r);
  renderManifest(r);
  renderAction(r);
}

function renderVerdict(r) {
  const banner = $("verdictBanner");
  const color  = r.verdict_color || "orange";
  banner.className = "verdict-banner " + color;
  const icons = { red: "☠", orange: "⚠", green: "✓" };
  $("verdictIcon").textContent = icons[color] || "?";
  $("verdictText").textContent = r.verdict || "UNKNOWN";

  const circ   = 2 * Math.PI * 32;
  const score  = Number(r.total_score) || 0;
  const offset = circ * (1 - score / 100);
  const ringColors = { red: "#e63946", orange: "#f4803a", green: "#2ec486" };
  const fg = $("ringFg");
  fg.style.stroke = ringColors[color] || "#f4803a";
  setTimeout(() => { fg.style.strokeDashoffset = offset; }, 50);
  const numEl = $("scoreNum");
  numEl.style.color = ringColors[color] || "#f4803a";
  animateCounter(numEl, 0, Math.round(score), 900);
}

function animateCounter(el, from, to, dur) {
  const start = performance.now();
  function tick(now) {
    const t = Math.min(1, (now - start) / dur);
    el.textContent = Math.round(from + (to - from) * t);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderMeta(r) {
  const m = r.manifest || {};
  const pills = [
    ["Package",      m.package_name    || "Unknown"],
    ["Version",      m.version_name    || "?"],
    ["Version Code", m.version_code    || "?"],
    ["Min SDK",      m.min_sdk         || "?"],
    ["Target SDK",   m.target_sdk      || "?"],
    ["File Size",    formatBytes(r.file_size_bytes || 0)],
    ["Scan Time",    (r.analysis_time_ms || 0) + " ms"],
  ];
  $("metaRow").innerHTML = pills.map(([l, v]) =>
    `<div class="meta-pill">
       <div class="meta-pill-label">${l}</div>
       <div class="meta-pill-value">${esc(String(v))}</div>
     </div>`
  ).join("");
}

function renderSummary(r) {
  const ul = $("riskList");
  const unique = [...new Set(r.risk_summary || [])];
  if (!unique.length) { ul.innerHTML = `<li>No high-confidence risk indicators found.</li>`; return; }
  ul.innerHTML = unique.map(s => {
    const cls = s.includes("[CRITICAL]") ? "critical" : s.includes("[HIGH]") ? "high" : "";
    return `<li class="${cls}">${esc(s)}</li>`;
  }).join("");
}

function renderPermissions(r) {
  const p = r.permissions || { cluster_matches: [], risky_permissions: [], malware_indicators: [] };

  // Clusters
  const clusterDiv = $("clusters");
  if (!(p.cluster_matches || []).length) {
    clusterDiv.innerHTML = `<p class="empty-note">No fraud permission clusters matched.</p>`;
  } else {
    clusterDiv.innerHTML = p.cluster_matches.map(c => `
      <div class="cluster ${c.severity}">
        <div class="cluster-head">
          <span class="cluster-name">${esc(c.cluster_name)}</span>
          <span class="sev-badge ${c.severity}">${c.severity}</span>
          <span style="font-size:11px;color:var(--txt-muted)">${(c.matched_permissions||[]).length} matched</span>
        </div>
        <div class="cluster-desc">${esc(c.description)}</div>
        <div class="perm-chips">
          ${(c.matched_permissions||[]).map(pm => `<span class="perm-chip">${esc(pm.replace("android.permission.",""))}</span>`).join("")}
        </div>
      </div>`).join("");
  }

  // Malware indicators
  const miDiv = $("malwareIndicators");
  if (!(p.malware_indicators || []).length) {
    miDiv.innerHTML = `<p class="empty-note">No malware behavior patterns detected.</p>`;
  } else {
    miDiv.innerHTML = p.malware_indicators.map(mi => `
      <div class="cluster ${mi.severity}">
        <div class="cluster-head">
          <span class="cluster-name">${esc(mi.name)}</span>
          <span class="sev-badge ${mi.severity}">${mi.severity}</span>
        </div>
        <div class="cluster-desc">${esc(mi.description)}</div>
        <div class="perm-chips">
          ${(mi.matched_patterns||[]).map(pat => `<span class="perm-chip">${esc(pat)}</span>`).join("")}
        </div>
      </div>`).join("");
  }

  // Permission table
  const tbody = $("permTableBody");
  if (!(p.risky_permissions || []).length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-note">No high-risk permissions found.</td></tr>`; return;
  }
  tbody.innerHTML = (p.risky_permissions || [])
    .sort((a, b) => b.risk_weight - a.risk_weight)
    .map(pf => {
      const pct   = (pf.risk_weight / 10) * 100;
      const color = pf.risk_weight >= 8 ? "var(--red)" : pf.risk_weight >= 6 ? "var(--orange)" : "var(--amber)";
      return `<tr>
        <td>${esc(pf.permission)}</td>
        <td>${esc(pf.category)}</td>
        <td><div class="weight-bar-cell"><span>${pf.risk_weight}/10</span>
          <div class="weight-bar-bg"><div class="weight-bar-fg" style="width:${pct}%;background:${color}"></div></div>
        </div></td></tr>`;
    }).join("");
}

function renderStrings(r) {
  const s = r.strings || {};

  // Suspicious domains + IPs
  const seenDomains = new Set();
  const dedupedSuspUrls = (s.suspicious_urls||[]).filter(u => {
    if (seenDomains.has(u.domain)) return false;
    seenDomains.add(u.domain); return true;
  });
  const dedupedIPs = [...new Set(s.hardcoded_ips||[])];
  const dedupedIPv6 = [...new Set(s.ipv6_addresses||[])];

  let sdHtml = "";
  dedupedSuspUrls.forEach(u => { sdHtml += iocItem("DOMAIN", u.domain, u.reason); });
  dedupedIPs.slice(0,20).forEach(ip => { sdHtml += iocItem("IPv4", ip, "Hardcoded IP — possible C2/tracker"); });
  dedupedIPv6.slice(0,5).forEach(ip => { sdHtml += iocItem("IPv6", ip, "Hardcoded IPv6 address"); });
  if (dedupedIPs.length > 20) sdHtml += `<div class="ioc-note" style="padding:6px 10px">...and ${dedupedIPs.length-20} more IPs</div>`;
  $("suspDomains").innerHTML = sdHtml || `<p class="empty-note">No suspicious domains or IPs found.</p>`;

  // Credentials
  const seenKeys = new Set();
  const dedupedKeys = (s.api_keys||[]).filter(k => { if (seenKeys.has(k.value)) return false; seenKeys.add(k.value); return true; });
  $("apiKeys").innerHTML = dedupedKeys.length
    ? dedupedKeys.map(k => iocItem(k.key_type.toUpperCase(), k.value, k.risk_note)).join("")
    : `<p class="empty-note">No hardcoded credentials found.</p>`;

  // Crypto wallets
  $("cryptoWallets").innerHTML = (s.crypto_wallets||[]).length
    ? (s.crypto_wallets||[]).map(w => iocItem(w.wallet_type, w.address, "Cryptocurrency wallet — possible fraud payment collection")).join("")
    : `<p class="empty-note">No cryptocurrency wallet addresses found.</p>`;

  // Cloud storage + WebSockets
  let cloudHtml = "";
  (s.cloud_storage_urls||[]).slice(0,10).forEach(u => { cloudHtml += iocItem("CLOUD", u, "Cloud storage endpoint"); });
  (s.websocket_endpoints||[]).slice(0,10).forEach(u => { cloudHtml += iocItem("WEBSOCKET", u, "WebSocket endpoint — possible real-time C2"); });
  $("cloudAndWs").innerHTML = cloudHtml || `<p class="empty-note">No cloud storage or WebSocket endpoints found.</p>`;

  // Phones & emails
  $("phones").innerHTML = (s.phone_numbers||[]).length
    ? [...new Set(s.phone_numbers)].map(p => iocItem("PHONE", p, "")).join("")
    : `<p class="empty-note">No phone numbers found.</p>`;
  $("emails").innerHTML = (s.emails||[]).length
    ? [...new Set(s.emails)].map(e => iocItem("EMAIL", e, "")).join("")
    : `<p class="empty-note">No email addresses found.</p>`;

  // All URLs
  const seenUrls = new Set();
  const dedupedUrls = (s.urls||[]).filter(u => { if (seenUrls.has(u.url)) return false; seenUrls.add(u.url); return true; });
  $("allUrls").innerHTML = dedupedUrls.length
    ? dedupedUrls.map(u =>
        `<div class="ioc-item">
          ${u.is_suspicious ? `<span class="ioc-tag">SUSPICIOUS</span>` : ""}
          <span class="ioc-val">${esc(u.url)}</span>
        </div>`).join("")
    : `<p class="empty-note">No URLs extracted.</p>`;
}

function renderIntelligence(r) {
  const intel = r.intelligence || {};

  // DNS
  const dnsDiv = $("dnsResults");
  const dnsRecs = intel.dns_records || [];
  if (!dnsRecs.length) {
    dnsDiv.innerHTML = `<p class="empty-note">No suspicious domains were resolved (no C2 domains detected or network unavailable).</p>`;
  } else {
    dnsDiv.innerHTML = dnsRecs.map(rec => {
      const rows = [];
      if (rec.a_records?.length)    rows.push(`<tr><td>A Records</td><td>${esc(rec.a_records.join(", "))}</td></tr>`);
      if (rec.aaaa_records?.length) rows.push(`<tr><td>AAAA Records</td><td>${esc(rec.aaaa_records.join(", "))}</td></tr>`);
      if (rec.mx_records?.length)   rows.push(`<tr><td>MX Records</td><td>${esc(rec.mx_records.join(", "))}</td></tr>`);
      if (rec.ns_records?.length)   rows.push(`<tr><td>NS Records</td><td>${esc(rec.ns_records.join(", "))}</td></tr>`);
      if (rec.error)                rows.push(`<tr><td>Status</td><td style="color:var(--txt-muted)">${esc(rec.error)}</td></tr>`);
      return `<div style="margin-bottom:16px">
        <div class="intel-domain-head">${esc(rec.domain)}</div>
        ${rows.length ? `<table class="intel-table"><tbody>${rows.join("")}</tbody></table>` : '<p class="empty-note" style="margin:4px 0">No records resolved</p>'}
      </div>`;
    }).join("<hr class='intel-sep'>");
  }

  // WHOIS
  const whoisDiv = $("whoisResults");
  const whoisRecs = intel.whois_records || [];
  if (!whoisRecs.length) {
    whoisDiv.innerHTML = `<p class="empty-note">No WHOIS data (no suspicious domains or network unavailable).</p>`;
  } else {
    whoisDiv.innerHTML = whoisRecs.map(rec => {
      const rows = [];
      if (rec.registrar)        rows.push(`<tr><td>Registrar</td><td>${esc(rec.registrar)}</td></tr>`);
      if (rec.creation_date)    rows.push(`<tr><td>Created</td><td>${esc(rec.creation_date)}${rec.days_old !== null ? ` <span style="color:${rec.is_new?'var(--red)':'var(--txt-muted)'}">(${rec.days_old} days ago${rec.is_new?' ⚠ NEW':''})</span>` : ''}</td></tr>`);
      if (rec.expiration_date)  rows.push(`<tr><td>Expires</td><td>${esc(rec.expiration_date)}</td></tr>`);
      if (rec.updated_date)     rows.push(`<tr><td>Updated</td><td>${esc(rec.updated_date)}</td></tr>`);
      if (rec.country)          rows.push(`<tr><td>Country</td><td>${esc(rec.country)}</td></tr>`);
      rows.push(`<tr><td>Privacy</td><td>${rec.privacy_protected ? '<span style="color:var(--orange)">Protected</span>' : 'Public'}</td></tr>`);
      if (rec.error)            rows.push(`<tr><td>Status</td><td style="color:var(--txt-muted)">${esc(rec.error)}</td></tr>`);
      return `<div style="margin-bottom:16px">
        <div class="intel-domain-head">${esc(rec.domain)}</div>
        <table class="intel-table"><tbody>${rows.join("")}</tbody></table>
      </div>`;
    }).join("<hr class='intel-sep'>");
  }

  // IP Intel
  const ipDiv = $("ipResults");
  const ipRecs = intel.ip_intel || [];
  if (!ipRecs.length) {
    ipDiv.innerHTML = `<p class="empty-note">No IPs analyzed (no hardcoded IPs detected or network unavailable).</p>`;
  } else {
    ipDiv.innerHTML = ipRecs.map(rec => {
      const rows = [];
      rows.push(`<tr><td>Type</td><td>${rec.is_private ? 'Private/Internal' : 'Public'}</td></tr>`);
      if (rec.country)          rows.push(`<tr><td>Country</td><td>${esc(rec.country)}</td></tr>`);
      if (rec.org)              rows.push(`<tr><td>Organization</td><td>${esc(rec.org)}</td></tr>`);
      if (rec.asn)              rows.push(`<tr><td>ASN</td><td>${esc(rec.asn)}</td></tr>`);
      if (rec.hosting_provider) rows.push(`<tr><td>ISP/Hosting</td><td>${esc(rec.hosting_provider)}</td></tr>`);
      rows.push(`<tr><td>Datacenter</td><td>${rec.is_datacenter ? '<span style="color:var(--orange)">Yes</span>' : 'No'}</td></tr>`);
      if (rec.reverse_dns)      rows.push(`<tr><td>Reverse DNS</td><td>${esc(rec.reverse_dns)}</td></tr>`);
      if (rec.risk_flags?.length) rows.push(`<tr><td>Risk Flags</td><td style="color:var(--red)">${esc(rec.risk_flags.join("; "))}</td></tr>`);
      return `<div style="margin-bottom:16px">
        <div class="intel-domain-head">${esc(rec.ip)}</div>
        <table class="intel-table"><tbody>${rows.join("")}</tbody></table>
      </div>`;
    }).join("<hr class='intel-sep'>");
  }
}

function renderManifest(r) {
  const m = r.manifest || {};
  const flags = [
    { label: "Debuggable",        val: m.debuggable,             bad: m.debuggable },
    { label: "Cleartext Traffic", val: m.uses_cleartext_traffic, bad: m.uses_cleartext_traffic },
    { label: "Backup Allowed",    val: m.backup_allowed,         bad: m.backup_allowed },
  ];
  $("flagsRow").innerHTML = flags.map(f =>
    `<div class="flag ${f.bad ? "bad" : "ok"}">
       <div class="flag-label">${f.label}</div>
       <div class="flag-value">${f.val ? "YES" : "NO"}</div>
     </div>`).join("");

  $("dangerousComps").innerHTML = (m.dangerous_components||[]).length
    ? (m.dangerous_components||[]).map(c =>
        `<div class="ioc-item"><span class="ioc-tag">${esc(c.component_type.toUpperCase())}</span>
         <div><div class="ioc-val">${esc(c.name)}</div><div class="ioc-note">${esc(c.danger_reason)}</div></div></div>`
      ).join("")
    : `<p class="empty-note">No dangerously exported components found.</p>`;

  $("manifestWarnings").innerHTML = (m.warnings||[]).length
    ? (m.warnings||[]).map(w => `<li>${esc(w)}</li>`).join("")
    : `<li>No manifest warnings.</li>`;
}

function renderAction(r) {
  $("actionText").textContent = r.recommended_action || "No action guidance available.";
  $("hashRow").innerHTML = `
    <div class="hash-entry"><span class="hash-key">SHA-256</span><span class="hash-val">${esc(r.sha256||"")}</span></div>
    <div class="hash-entry"><span class="hash-key">MD5</span><span class="hash-val">${esc(r.md5||"")}</span></div>`;
  $("metaHash").innerHTML = `
    <div class="hash-entry"><span class="hash-key">Filename</span><span class="hash-val">${esc(r.filename||"")}</span></div>
    <div class="hash-entry"><span class="hash-key">Timestamp</span><span class="hash-val">${esc(r.analysis_timestamp||"")}</span></div>
    <div class="hash-entry"><span class="hash-key">Scan Time</span><span class="hash-val">${r.analysis_time_ms||0} ms</span></div>`;

  // JSON export
  $("exportJsonBtn").onclick = () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], {type: "application/json"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `frauddroid-report-${(currentReport.filename||"apk").replace(".apk","")}-${Date.now()}.json`;
    a.click();
  };
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
    btn.classList.add("active");
    $("tab-" + btn.dataset.tab).classList.remove("hidden");
  });
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function iocItem(tag, val, note) {
  return `<div class="ioc-item">
    <span class="ioc-tag">${esc(tag)}</span>
    <div><div class="ioc-val">${esc(val)}</div>${note ? `<div class="ioc-note">${esc(note)}</div>` : ""}</div>
  </div>`;
}

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatBytes(b) {
  b = Number(b) || 0;
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b/1024).toFixed(1) + " KB";
  return (b/1048576).toFixed(2) + " MB";
}
