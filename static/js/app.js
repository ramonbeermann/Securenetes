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

searchInput?.addEventListener("input", applyFindingFilters);
severityFilter?.addEventListener("change", applyFindingFilters);
