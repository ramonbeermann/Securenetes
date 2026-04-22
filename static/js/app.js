const root = document.documentElement;
const storedTheme = localStorage.getItem("theme");
if (storedTheme === "light") root.classList.add("light");

const toggle = document.getElementById("theme-toggle");
if (toggle) {
  toggle.addEventListener("click", () => {
    root.classList.toggle("light");
    localStorage.setItem("theme", root.classList.contains("light") ? "light" : "dark");
  });
}

const startScan = document.getElementById("start-scan");
if (startScan) {
  startScan.addEventListener("click", async () => {
    startScan.disabled = true;
    const res = await fetch("/api/scans/start", { method: "POST" });
    const data = await res.json();
    alert(data.message);
    window.location.reload();
  });
}

const searchInput = document.getElementById("finding-search");
const severityFilter = document.getElementById("severity-filter");
const findingsTable = document.getElementById("findings-table");

function applyFindingFilters() {
  if (!findingsTable) return;
  const term = (searchInput?.value || "").toLowerCase();
  const severity = severityFilter?.value || "";
  findingsTable.querySelectorAll("tbody tr").forEach((row) => {
    const text = row.innerText.toLowerCase();
    const rowSeverity = row.getAttribute("data-severity");
    const okSearch = text.includes(term);
    const okSeverity = !severity || rowSeverity === severity;
    row.style.display = okSearch && okSeverity ? "" : "none";
  });
}

function normalizePayload(formData) {
  return {
    cluster_url: (formData.get("cluster_url") || "").toString().trim(),
    token: (formData.get("token") || "").toString().trim(),
    ca_cert: ((formData.get("ca_cert") || "").toString().trim() || null),
    namespace: ((formData.get("namespace") || "").toString().trim() || null),
  };
}

async function callKubeApi(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  return res.json();
}

const kubeForm = document.getElementById("kube-setup-form");
const kubeTestBtn = document.getElementById("kube-test-btn");
const kubeSaveBtn = document.getElementById("kube-save-btn");
const kubeStatus = document.getElementById("kube-status");

function setKubeStatus(text) {
  if (kubeStatus) kubeStatus.textContent = text;
}

if (kubeForm && kubeTestBtn && kubeSaveBtn) {
  kubeTestBtn.addEventListener("click", async () => {
    const payload = normalizePayload(new FormData(kubeForm));
    setKubeStatus("⏳ teste Verbindung");

    const data = await callKubeApi("/api/kube/test", payload);
    setKubeStatus(data.ok ? "✅ verbunden" : `❌ ${data.message}`);
  });

  kubeSaveBtn.addEventListener("click", async () => {
    const payload = normalizePayload(new FormData(kubeForm));
    setKubeStatus("⏳ speichere Konfiguration");

    const data = await callKubeApi("/api/kube/save", payload);
    if (data.ok) {
      setKubeStatus("✅ verbunden");
      window.location.href = "/";
      return;
    }

    setKubeStatus(`❌ ${data.message}`);
  });
}

searchInput?.addEventListener("input", applyFindingFilters);
severityFilter?.addEventListener("change", applyFindingFilters);
