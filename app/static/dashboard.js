const attackColors = {
  ddos: "#FF4757", portscan: "#FFB84D", bruteforce: "#FFB84D",
  sqli: "#FF4757", phishing: "#FFB84D", malware: "#FF4757", normal: "#3DDC84",
};

let attackChart, timelineChart;
let selectedEventId = null;
let maxSeenEventId = 0;
let firstLoad = true;

function spawnBlip(color, big) {
  const radar = document.getElementById("radar");
  if (!radar) return;
  const angle = Math.random() * Math.PI * 2;
  const radius = 15 + Math.random() * 35;
  const x = 50 + Math.cos(angle) * radius;
  const y = 50 + Math.sin(angle) * radius;
  const blip = document.createElement("div");
  blip.className = "radar-blip";
  blip.style.left = x + "%";
  blip.style.top = y + "%";
  blip.style.background = color;
  blip.style.boxShadow = `0 0 8px ${color}`;
  if (big) { blip.style.width = "8px"; blip.style.height = "8px"; }
  radar.appendChild(blip);
  setTimeout(() => blip.remove(), 2600);
}


function initCharts() {
  const ctxA = document.getElementById("attackChart");
  attackChart = new Chart(ctxA, {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#5E7186", font: { family: "JetBrains Mono", size: 9 } }, grid: { display: false } },
        y: { ticks: { color: "#5E7186", font: { family: "JetBrains Mono", size: 9 } }, grid: { color: "#1E2A38" }, beginAtZero: true },
      },
    },
  });

  const ctxT = document.getElementById("timelineChart");
  timelineChart = new Chart(ctxT, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "Normal", data: [], borderColor: "#4FD8E8", backgroundColor: "transparent", tension: 0.3, pointRadius: 0 },
        { label: "Attacks", data: [], borderColor: "#FF4757", backgroundColor: "transparent", tension: 0.3, pointRadius: 0 },
      ],
    },
    options: {
      plugins: { legend: { labels: { color: "#8FA3B8", font: { family: "JetBrains Mono", size: 10 } } } },
      scales: {
        x: { ticks: { display: false }, grid: { color: "#1E2A38" } },
        y: { ticks: { color: "#5E7186", font: { family: "JetBrains Mono", size: 9 } }, grid: { color: "#1E2A38" }, beginAtZero: true },
      },
    },
  });
}

function fmtTime(iso) {
  const d = new Date(iso + "Z");
  return d.toLocaleTimeString("en-US", { hour12: false });
}

async function refreshEvents() {
  const res = await fetch("/api/events?limit=60");
  const events = await res.json();
  const body = document.getElementById("eventsBody");
  body.innerHTML = "";
  events.forEach((e) => {
    if (!firstLoad && e.id > maxSeenEventId) {
      const bColor = e.classification === "normal" ? "#3DDC84" : (attackColors[e.classification] || "#FFB84D");
      spawnBlip(bColor, e.classification !== "normal");
    }
    const tr = document.createElement("tr");
  
  
  
  
  
    
    tr.onclick = () => openReport(e.id);
    const color = e.classification === "normal" ? "var(--green)" : attackColors[e.classification] || "var(--amber)";
    tr.innerHTML = `
      <td class="dim">${fmtTime(e.ts)}</td>
      <td>${e.src_ip}</td>
      <td class="dim">${e.port}</td>
      <td class="dim">${e.protocol}</td>
      <td style="color:${color}">${e.label}</td>
      <td class="dim">${(e.confidence * 100).toFixed(1)}%</td>
      <td><span class="pill ${e.status}">${e.status.toUpperCase()}</span></td>
      <td class="dim">&#8250;</td>
    `; 
body.appendChild(tr);
  });
  if (events.length) {
    maxSeenEventId = Math.max(maxSeenEventId, ...events.map((e) => e.id));
  }
  firstLoad = false;
}
  

async function refreshStats() {
  const res = await fetch("/api/stats");
  const s = await res.json();
  document.getElementById("statTotal").textContent = s.total_packets.toLocaleString();
  document.getElementById("statAttacks").textContent = s.total_attacks.toLocaleString();
  document.getElementById("statBlocked").textContent = s.blocked_ips;

  const activeThreats = Object.values(s.by_type).reduce((a, b) => a + b, 0) > 0
    ? Math.min(20, s.total_attacks) : 0;
  const recentAttacks = s.timeline.length ? s.timeline[s.timeline.length - 1].attacks : 0;
  document.getElementById("statActive").textContent = recentAttacks;

  const pill = document.getElementById("statusPill");
  const text = document.getElementById("statusText");
  pill.classList.remove("elevated", "critical");
  if (recentAttacks > 5) { pill.classList.add("critical"); text.textContent = "UNDER ATTACK"; }
  else if (recentAttacks > 0) { pill.classList.add("elevated"); text.textContent = "ELEVATED"; }
  else { text.textContent = "SECURE"; }

  const labels = Object.keys(attackColors).filter((k) => k !== "normal");
  attackChart.data.labels = labels.map((l) => l.toUpperCase());
  attackChart.data.datasets[0].data = labels.map((l) => s.by_type[l] || 0);
  attackChart.data.datasets[0].backgroundColor = labels.map((l) => attackColors[l]);
  attackChart.update();

  timelineChart.data.labels = s.timeline.map((t) => t.minute.split("T")[1] || "");
  timelineChart.data.datasets[0].data = s.timeline.map((t) => t.normal);
  timelineChart.data.datasets[1].data = s.timeline.map((t) => t.attacks);
  timelineChart.update();

  document.getElementById("autoResponseToggle").checked = s.auto_response.enabled;
}

async function refreshBlocked() {
  const res = await fetch("/api/blocked");
  const rows = await res.json();
  const el = document.getElementById("blockedList");
  el.innerHTML = "";
  if (rows.length === 0) {
    el.innerHTML = `<div class="dim mono" style="text-align:center;padding:20px;font-size:11px;">No sources blocked</div>`;
    return;
  }
    events.forEach((e) => {
    if (!firstLoad && e.id > maxSeenEventId) {
      const bColor = e.classification === "normal" ? "#3DDC84" : (attackColors[e.classification] || "#FFB84D");
      spawnBlip(bColor, e.classification !== "normal");
    }
    const tr = document.createElement("tr");
    
    div.className = "blocked-item";
    div.innerHTML = `
      <div><div class="ip">${r.ip}</div><div class="reason">${r.reason}</div></div>
      <button title="Unblock">&#128275;</button>
    `;
    div.querySelector("button").onclick = async () => {
      await fetch("/api/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: r.ip }) });
      refreshBlocked();
    };
    el.appendChild(div);
  });
}

async function openReport(id) {
  selectedEventId = id;
  const res = await fetch(`/api/report/${id}`);
  const data = await res.json();
  document.getElementById("modalBody").textContent = data.text;
  document.getElementById("modalOverlay").classList.remove("hidden");
}

document.getElementById("modalClose").onclick = () => {
  document.getElementById("modalOverlay").classList.add("hidden");
};
document.getElementById("modalOverlay").onclick = (e) => {
  if (e.target.id === "modalOverlay") e.currentTarget.classList.add("hidden");
};

document.getElementById("blockBtn").onclick = async () => {
  const res = await fetch("/api/events?limit=60");
  const events = await res.json();
  const ev = events.find((e) => e.id === selectedEventId);
  if (ev) {
    await fetch("/api/block", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: ev.src_ip, reason: ev.label }) });
    document.getElementById("modalOverlay").classList.add("hidden");
    refreshBlocked(); refreshEvents();
  }
};

document.getElementById("autoResponseToggle").onchange = async (e) => {
  await fetch("/api/auto-response", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: e.target.checked }) });
};

function tickClock() {
  document.getElementById("clock").textContent = new Date().toLocaleString();
}

initCharts();
tickClock();
setInterval(tickClock, 1000);
refreshEvents(); refreshStats(); refreshBlocked();
setInterval(refreshEvents, 1500);
setInterval(refreshStats, 2000);
setInterval(refreshBlocked, 3000);
