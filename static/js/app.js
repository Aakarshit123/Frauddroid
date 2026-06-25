/* ============================================================
   FraudDroid — Frontend Logic
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

// ---------------------------------------------------------------------------
// Progress — stays animated until response arrives (no fake timeout)
// ---------------------------------------------------------------------------

const STEPS = [
  "Unpacking APK archive...",
  "Parsing AndroidManifest.xml...",
  "Extracting permission list...",
  "Running permission cluster analysis...",
  "Extracting strings from .dex...",
  "Scanning for hardcoded IOCs...",
  "Running fraud signature matching...",
  "Computing risk score...",
  "Building report...",
];

let stepTimer = null;
let stepIdx   = 0;
let barPct    = 0;

function startProgressAnimation() {
  stepIdx = 0; barPct = 0;
  $("progressLabel").textContent = STEPS[0];
  $("progressBar").style.width = "5%";

  stepTimer = setInterval(() => {
    if (stepIdx < STEPS.length - 1) {
      stepIdx++;
      // Advance bar but cap at 92% — last push happens on response
      barPct = Math.min(92, 5 + (stepIdx / (STEPS.length - 1)) * 87);
      $("progressBar").style.width = barPct + "%";
      $("progressLabel").textContent = STEPS[stepIdx];
    }
    // Once at last step, keep label but don't advance bar further
  }, 2800);
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

    if (data.error) { alert("Analysis error: " + data.error); resetUI(); return; }

    currentReport = data;
    // Small delay so "Done!" is visible
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
  $("progressSection").classList.add("hidden");
  $("reportSection").classList.remove("hidden");
  renderVerdict(r);
  renderMeta(r);
  renderSummary(r);
  renderPermissions(r);
  renderStrings(r);
  renderManifest(r);
  renderAction(r);
}

function renderVerdict(r) {
  const banner = $("verdictBanner");
  const color  = r.verdict_color;
  banner.className = "verdict-banner " + color;
  const icons = { red: "☠", orange: "⚠", green: "✓" };
  $("verdictIcon").textContent = icons[color] || "?";
  $("verdictText").textContent = r.verdict;

  const circ   = 2 * Math.PI * 32;
  const offset = circ * (1 - r.total_score / 100);
  const ringColors = { red: "#e63946", orange: "#f4803a", green: "#2ec486" };
  const fg = $("ringFg");
  fg.style.stroke = ringColors[color];
  setTimeout(() => { fg.style.strokeDashoffset = offset; }, 50);
  const numEl = $("scoreNum");
  numEl.style.color = ringColors[color];
  animateCounter(numEl, 0, Math.round(r.total_score), 900);
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
  const m = r.manifest;
  const pills = [
    ["Package",      m.package_name    || "Unknown"],
    ["Version",      m.version_name    || "?"],
    ["Version Code", m.version_code    || "?"],
    ["Min SDK",      m.min_sdk         || "?"],
    ["Target SDK",   m.target_sdk      || "?"],
    ["File Size",    formatBytes(r.file_size_bytes)],
    ["Scan Time",    r.analysis_time_ms + " ms"],
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
  // Deduplicate summary lines
  const unique = [...new Set(r.risk_summary)];
  if (!unique.length) { ul.innerHTML = `<li>No high-confidence risk indicators found.</li>`; return; }
  ul.innerHTML = unique.map(s => {
    const cls = s.includes("[CRITICAL]") ? "critical" : s.includes("[HIGH]") ? "high" : "";
    return `<li class="${cls}">${esc(s)}</li>`;
  }).join("");
}

function renderPermissions(r) {
  const p = r.permissions;
  const clusterDiv = $("clusters");
  if (!p.cluster_matches.length) {
    clusterDiv.innerHTML = `<p class="empty-note">No fraud permission clusters matched.</p>`;
  } else {
    clusterDiv.innerHTML = p.cluster_matches.map(c => `
      <div class="cluster ${c.severity}">
        <div class="cluster-head">
          <span class="cluster-name">${esc(c.cluster_name)}</span>
          <span class="sev-badge ${c.severity}">${c.severity}</span>
          <span style="font-size:11px;color:var(--txt-muted)">${c.matched_permissions.length} permissions matched</span>
        </div>
        <div class="cluster-desc">${esc(c.description)}</div>
        <div class="perm-chips">
          ${c.matched_permissions.map(p => `<span class="perm-chip">${esc(p.replace("android.permission.",""))}</span>`).join("")}
        </div>
      </div>`).join("");
  }

  const tbody = $("permTableBody");
  if (!p.risky_permissions.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-note">No high-risk permissions found.</td></tr>`; return;
  }
  tbody.innerHTML = p.risky_permissions
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
  const s = r.strings;

  // Deduplicate suspicious URLs by domain
  const seenDomains = new Set();
  const dedupedSuspUrls = s.suspicious_urls.filter(u => {
    if (seenDomains.has(u.domain)) return false;
    seenDomains.add(u.domain); return true;
  });

  // Deduplicate IPs
  const dedupedIPs = [...new Set(s.hardcoded_ips)];

  const sdiv = $("suspDomains");
  let sdHtml = "";
  dedupedSuspUrls.forEach(u => { sdHtml += iocItem("DOMAIN", u.domain, u.reason); });
  dedupedIPs.slice(0, 20).forEach(ip => { sdHtml += iocItem("IP", ip, "Hardcoded IP — possible C2/tracker"); });
  if (dedupedIPs.length > 20) sdHtml += `<div class="ioc-note" style="padding:6px 10px">...and ${dedupedIPs.length - 20} more IPs</div>`;
  sdiv.innerHTML = sdHtml || `<p class="empty-note">No suspicious domains or IPs found.</p>`;

  // Deduplicate API keys by value
  const seenKeys = new Set();
  const dedupedKeys = s.api_keys.filter(k => { if (seenKeys.has(k.value)) return false; seenKeys.add(k.value); return true; });
  $("apiKeys").innerHTML = dedupedKeys.length
    ? dedupedKeys.map(k => iocItem(k.key_type.toUpperCase(), k.value, k.risk_note)).join("")
    : `<p class="empty-note">No hardcoded credentials found.</p>`;

  $("phones").innerHTML = s.phone_numbers.length
    ? [...new Set(s.phone_numbers)].map(p => iocItem("PHONE", p, "")).join("")
    : `<p class="empty-note">No phone numbers found.</p>`;

  $("emails").innerHTML = s.emails.length
    ? [...new Set(s.emails)].map(e => iocItem("EMAIL", e, "")).join("")
    : `<p class="empty-note">No email addresses found.</p>`;

  // Deduplicate all URLs
  const seenUrls = new Set();
  const dedupedUrls = s.urls.filter(u => { if (seenUrls.has(u.url)) return false; seenUrls.add(u.url); return true; });
  $("allUrls").innerHTML = dedupedUrls.length
    ? dedupedUrls.map(u =>
        `<div class="ioc-item">
          ${u.is_suspicious ? `<span class="ioc-tag">SUSPICIOUS</span>` : ""}
          <span class="ioc-val">${esc(u.url)}</span>
        </div>`).join("")
    : `<p class="empty-note">No URLs extracted.</p>`;
}

function iocItem(tag, val, note) {
  return `<div class="ioc-item">
    <span class="ioc-tag">${esc(tag)}</span>
    <div><div class="ioc-val">${esc(val)}</div>${note ? `<div class="ioc-note">${esc(note)}</div>` : ""}</div>
  </div>`;
}

function renderManifest(r) {
  const m = r.manifest;
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

  $("dangerousComps").innerHTML = m.dangerous_components.length
    ? m.dangerous_components.map(c =>
        `<div class="ioc-item"><span class="ioc-tag">${esc(c.component_type.toUpperCase())}</span>
         <div><div class="ioc-val">${esc(c.name)}</div><div class="ioc-note">${esc(c.danger_reason)}</div></div></div>`
      ).join("")
    : `<p class="empty-note">No dangerously exported components found.</p>`;

  $("manifestWarnings").innerHTML = m.warnings.length
    ? m.warnings.map(w => `<li>${esc(w)}</li>`).join("")
    : `<li>No manifest warnings.</li>`;
}

function renderAction(r) {
  $("actionText").textContent = r.recommended_action;
  $("hashRow").innerHTML = `
    <div class="hash-entry"><span class="hash-key">SHA-256</span><span class="hash-val">${esc(r.sha256)}</span></div>
    <div class="hash-entry"><span class="hash-key">MD5</span><span class="hash-val">${esc(r.md5)}</span></div>`;
  $("metaHash").innerHTML = `
    <div class="hash-entry"><span class="hash-key">Filename</span><span class="hash-val">${esc(r.filename)}</span></div>
    <div class="hash-entry"><span class="hash-key">Timestamp</span><span class="hash-val">${esc(r.analysis_timestamp)}</span></div>
    <div class="hash-entry"><span class="hash-key">Scan Time</span><span class="hash-val">${r.analysis_time_ms} ms</span></div>`;
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
function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function formatBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b/1024).toFixed(1) + " KB";
  return (b/1048576).toFixed(2) + " MB";
}
