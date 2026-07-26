// PROTOTYPE — Three role-aware dashboard information architectures,
// switchable via ?variant= and ?role= on one throwaway route.

const servers = [
  {
    id: "srv_01J8ATLAS",
    name: "Atlas GPU",
    subtitle: "NVIDIA GPU Compute Server",
    health: "Degraded",
    healthKey: "degraded",
    cpu: 68,
    memory: 74,
    disk: 61,
    gpu: 92,
    vram: 88,
    spark: [40, 46, 51, 55, 49, 61, 68, 72, 66, 71, 68, 70],
    incident: "Required Service failed",
    incidentDetail:
      "slurmd.service has been inactive for 18 minutes. The server remains observable.",
    profile: "NVIDIA GPU Compute · r4",
    address: "atlas.lab.internal",
    inventory: "2 × NVIDIA RTX 6000 Ada",
    services: [
      ["node_exporter.service", "Active"],
      ["dcgm-exporter.service", "Active"],
      ["slurmd.service", "Failed"],
    ],
    event: "Server Incident opened 18 minutes ago",
  },
  {
    id: "srv_01J8NOVA",
    name: "Nova Compute",
    subtitle: "General Linux Server",
    health: "Healthy",
    healthKey: "healthy",
    cpu: 34,
    memory: 47,
    disk: 39,
    gpu: 58,
    vram: 42,
    spark: [28, 31, 29, 37, 43, 39, 35, 41, 38, 33, 34, 36],
    incident: "No active health rules",
    incidentDetail: "All required observations are present and within profile thresholds.",
    profile: "NVIDIA GPU Compute · r3",
    address: "nova.lab.internal",
    inventory: "1 × NVIDIA A5000",
    services: [
      ["node_exporter.service", "Active"],
      ["dcgm-exporter.service", "Active"],
      ["jupyterhub.service", "Active"],
    ],
    event: "Recovered to Healthy 2 days ago",
  },
];

const variantNames = {
  A: "Fleet cards + workspace",
  B: "Operations ledger",
  C: "Focused server story",
};

const state = {
  variant: readParam("variant", "A").toUpperCase(),
  role: readParam("role", "user").toLowerCase(),
  selected: readParam("server", servers[0].id),
};

if (!variantNames[state.variant]) state.variant = "A";
if (!["user", "admin"].includes(state.role)) state.role = "user";
if (!servers.some((server) => server.id === state.selected)) state.selected = servers[0].id;

function readParam(name, fallback) {
  return new URLSearchParams(window.location.search).get(name) || fallback;
}

function updateUrl(changes) {
  const url = new URL(window.location.href);
  Object.entries(changes).forEach(([key, value]) => url.searchParams.set(key, value));
  window.history.replaceState({}, "", url);
}

function selectedServer() {
  return servers.find((server) => server.id === state.selected) || servers[0];
}

function healthLabel(server) {
  return `
    <span class="health-label health-${server.healthKey}">
      <span class="health-dot"></span>${server.health}
    </span>
  `;
}

function metric(name, value, color = "var(--cyan)") {
  return `
    <div class="metric-row">
      <span class="metric-name">${name}</span>
      <span class="meter" style="--meter-color:${color}">
        <span style="--value:${value}%"></span>
      </span>
      <span class="metric-value">${value}%</span>
    </div>
  `;
}

function spark(values, color = "var(--cyan)") {
  return `
    <div class="spark" style="--spark-color:${color}">
      ${values.map((value) => `<span style="--height:${value}%"></span>`).join("")}
    </div>
  `;
}

function metricTiles(server) {
  return [
    ["CPU", server.cpu],
    ["Memory", server.memory],
    ["Disk", server.disk],
    ["GPU", server.gpu],
    ["VRAM", server.vram],
  ]
    .map(
      ([name, value]) => `
      <div class="metric-tile">
        <span>${name}</span>
        <strong>${value}%</strong>
        <span>current usage</span>
      </div>`,
    )
    .join("");
}

function sharedIdentity() {
  const label = state.role === "admin" ? "Lab Administrator" : "Lab User";
  return `
    <div class="identity">
      <span>${label}</span>
      <span class="avatar">${state.role === "admin" ? "LA" : "LU"}</span>
    </div>
  `;
}

function variantA() {
  const selected = selectedServer();
  return `
    <main class="variant-a">
      <header class="a-topbar">
        <div class="brand"><span class="brand-mark">LS</span><span>Lab Server Health</span></div>
        ${sharedIdentity()}
      </header>
      <div class="a-shell">
        <section class="a-heading">
          <div>
            <span class="eyebrow">Fleet overview</span>
            <h1>Two servers, one needs attention.</h1>
          </div>
          <div class="fleet-summary">
            <div class="summary-chip"><strong class="health-healthy">1</strong><span>Healthy</span></div>
            <div class="summary-chip"><strong class="health-degraded">1</strong><span>Degraded</span></div>
          </div>
        </section>

        <section class="a-fleet" aria-label="Servers">
          ${servers
            .map(
              (server) => `
            <article class="server-card ${server.id === state.selected ? "selected" : ""}" data-server="${server.id}">
              <div class="server-card-head">
                <div>
                  <span class="eyebrow">${server.subtitle}</span>
                  <h2>${server.name}</h2>
                </div>
                ${healthLabel(server)}
              </div>
              <div class="server-card-metrics">
                <div>
                  ${metric("CPU", server.cpu)}
                  ${metric("Memory", server.memory, "var(--blue)")}
                  ${metric("GPU", server.gpu, "var(--purple)")}
                  ${metric("VRAM", server.vram, "var(--degraded)")}
                </div>
                <div>
                  <div class="card-spark-label"><span>CPU · 12h</span><span>${server.cpu}%</span></div>
                  ${spark(server.spark)}
                </div>
              </div>
            </article>`,
            )
            .join("")}
        </section>

        <section class="a-detail">
          <article class="detail-panel">
            <div class="detail-title">
              <div>
                <span class="eyebrow">Selected server</span>
                <h2>${selected.name}</h2>
              </div>
              ${healthLabel(selected)}
            </div>
            <div class="metric-tiles">${metricTiles(selected)}</div>
            <div class="history-chart" aria-label="Thirty-day Resource Usage sample">
              ${[45, 38, 52, 49, 60, 48, 66, 72, 59, 62, 70, 68, 77, 64, 71, 67, 74, 69]
                .map((value) => `<span style="--height:${value}%"></span>`)
                .join("")}
            </div>
            <div class="card-spark-label"><span>30 days ago</span><span>Resource Usage · now</span></div>
          </article>

          <aside class="detail-panel">
            <div class="detail-title">
              <div>
                <span class="eyebrow">${state.role === "admin" ? "Operational detail" : "Health summary"}</span>
                <h3>${selected.incident}</h3>
              </div>
              <span class="tag ${selected.healthKey === "degraded" ? "tag-warn" : "tag-ok"}">${selected.event}</span>
            </div>
            <div class="cause-box">
              <strong>${selected.health}</strong>
              <p>${state.role === "admin" ? selected.incidentDetail : userSafeSummary(selected)}</p>
            </div>
            ${
              state.role === "admin"
                ? `
                <div class="service-list">
                  ${selected.services
                    .map(
                      ([name, serviceState]) => `
                    <div class="service-row">
                      <span>${name}</span>
                      <span class="${serviceState === "Failed" ? "health-degraded" : "health-healthy"}">${serviceState}</span>
                    </div>`,
                    )
                    .join("")}
                </div>
                <div class="service-row"><span>Server Profile</span><span>${selected.profile}</span></div>
                <div class="service-row"><span>Scrape address</span><span>${selected.address}</span></div>
              `
                : `<p class="muted">Detailed services, errors, alerts, and configuration are available only to Lab Administrators.</p>`
            }
          </aside>
        </section>
      </div>
    </main>
  `;
}

function variantB() {
  const selected = selectedServer();
  const roleNav =
    state.role === "admin"
      ? ["Fleet", "Incidents", "Enrollment", "Profiles", "Settings"]
      : ["Fleet", "History"];
  return `
    <main class="variant-b">
      <aside class="b-sidebar">
        <div class="brand"><span class="brand-mark">LS</span><span>Lab Health</span></div>
        <nav class="b-nav">
          ${roleNav.map((item, index) => `<span class="${index === 0 ? "active" : ""}">${item}</span>`).join("")}
        </nav>
        <div class="b-side-foot">${state.role === "admin" ? "Lab Administrator controls enabled" : "Summary disclosure only"}</div>
      </aside>

      <section class="b-main">
        <header class="b-toolbar">
          <div>
            <span class="eyebrow">Operations ledger</span>
            <h1>Fleet</h1>
          </div>
          <div class="b-pulse">
            <span><strong>2</strong> observed</span>
            <span><strong class="health-degraded">1</strong> degraded</span>
            <span><strong>15s</strong> fresh</span>
          </div>
        </header>

        <div class="b-table-wrap">
          <table class="b-table">
            <thead>
              <tr>
                <th>Server</th><th>Health</th><th>CPU</th><th>Memory</th><th>Disk</th><th>GPU</th><th>VRAM</th>
                ${state.role === "admin" ? "<th>Cause</th><th>Profile</th>" : ""}
              </tr>
            </thead>
            <tbody>
              ${servers
                .map(
                  (server) => `
                <tr class="${server.id === state.selected ? "selected" : ""}" data-server="${server.id}">
                  <td><strong>${server.name}</strong><small>${server.id}</small></td>
                  <td>${healthLabel(server)}</td>
                  <td>${server.cpu}%</td><td>${server.memory}%</td><td>${server.disk}%</td><td>${server.gpu}%</td><td>${server.vram}%</td>
                  ${state.role === "admin" ? `<td>${server.incident}</td><td>${server.profile}</td>` : ""}
                </tr>`,
                )
                .join("")}
            </tbody>
          </table>
        </div>

        <div class="b-inspector">
          <article class="b-sheet">
            <div class="b-sheet-head"><h2>${selected.name} · evidence</h2>${healthLabel(selected)}</div>
            <dl class="b-dl">
              <dt>Server Health</dt><dd>${selected.health}</dd>
              <dt>Current explanation</dt><dd>${state.role === "admin" ? selected.incidentDetail : userSafeSummary(selected)}</dd>
              <dt>GPU inventory</dt><dd>${selected.inventory}</dd>
              <dt>Metric History</dt><dd>30 days · latest observation 15 seconds ago</dd>
              ${
                state.role === "admin"
                  ? `
                    <dt>Server ID</dt><dd>${selected.id}</dd>
                    <dt>Server Profile</dt><dd>${selected.profile}</dd>
                    <dt>Scrape address</dt><dd>${selected.address}</dd>
                  `
                  : ""
              }
            </dl>
          </article>
          <aside class="b-sheet">
            <div class="b-sheet-head"><h3>${state.role === "admin" ? "Operational timeline" : "Health timeline"}</h3><span class="tag">30 days</span></div>
            <ul class="b-log">
              <li><time>18 min ago</time>${selected.event}</li>
              <li><time>2 hours ago</time>Resource Usage sample retained</li>
              <li><time>Yesterday</time>${state.role === "admin" ? "Collector configuration r4 verified" : "Observation remained available"}</li>
            </ul>
          </aside>
        </div>
      </section>
    </main>
  `;
}

function variantC() {
  const selected = selectedServer();
  return `
    <main class="variant-c">
      <header class="c-masthead">
        <div class="c-brand">Lab Server Health</div>
        <div class="c-role">${state.role === "admin" ? "Lab Administrator view" : "Lab User view"}</div>
      </header>

      <div class="c-layout">
        <aside class="c-fleet-rail">
          <span class="eyebrow">Current capacity</span>
          <h1>Choose a server, understand it fast.</h1>
          <p>Health explains whether the server needs attention. Resource Usage shows what capacity is active right now.</p>
          <div class="c-server-list">
            ${servers
              .map(
                (server) => `
              <button class="c-server-button ${server.id === state.selected ? "selected" : ""}" data-server="${server.id}">
                <span class="health-dot health-${server.healthKey}"></span>
                <span><strong>${server.name}</strong><small>${server.health} · ${server.subtitle}</small></span>
                <span class="c-score">${server.gpu}%</span>
              </button>`,
              )
              .join("")}
          </div>
        </aside>

        <article class="c-focus">
          <header class="c-focus-head">
            <div><span class="eyebrow">${selected.subtitle}</span><h2>${selected.name}</h2></div>
            <span class="c-health-word health-${selected.healthKey}">${selected.health}</span>
          </header>
          <section class="c-vitals">
            ${[
              ["CPU", selected.cpu],
              ["Memory", selected.memory],
              ["Disk", selected.disk],
              ["GPU", selected.gpu],
              ["VRAM", selected.vram],
            ]
              .map(([name, value]) => `<div class="c-vital"><strong>${value}%</strong><span>${name} usage</span></div>`)
              .join("")}
          </section>
          <section class="c-story">
            <div class="c-story-section">
              <h3>What changed</h3>
              <div class="c-note">
                <strong>${selected.incident}</strong>
                <p>${state.role === "admin" ? selected.incidentDetail : userSafeSummary(selected)}</p>
              </div>
              <div class="c-timeline" aria-label="Thirty-day health timeline">
                <i style="--left:8%;--bottom:34%"></i>
                <i style="--left:31%;--bottom:48%"></i>
                <i style="--left:55%;--bottom:39%"></i>
                <i class="${selected.healthKey === "degraded" ? "warn" : ""}" style="--left:86%;--bottom:62%"></i>
              </div>
            </div>
            <div class="c-story-section">
              <h3>${state.role === "admin" ? "Operate" : "Capacity context"}</h3>
              ${
                state.role === "admin"
                  ? `
                    <div class="c-admin-grid">
                      <div class="c-admin-row"><span>Server ID</span><strong>${selected.id}</strong></div>
                      <div class="c-admin-row"><span>Profile</span><strong>${selected.profile}</strong></div>
                      <div class="c-admin-row"><span>Inventory</span><strong>${selected.inventory}</strong></div>
                      ${selected.services
                        .map(
                          ([name, serviceState]) =>
                            `<div class="c-admin-row"><span>${name}</span><strong class="${serviceState === "Failed" ? "health-degraded" : ""}">${serviceState}</strong></div>`,
                        )
                        .join("")}
                    </div>
                  `
                  : `
                    <p class="muted">GPU activity and VRAM consumption describe current work; high usage alone does not mean the server is unhealthy.</p>
                    ${metric("GPU", selected.gpu, "#4b7661")}
                    ${metric("VRAM", selected.vram, "#b67f26")}
                    <p class="muted">Operational services, errors, alerts, and configuration remain private to Lab Administrators.</p>
                  `
              }
            </div>
          </section>
        </article>
      </div>
    </main>
  `;
}

function userSafeSummary(server) {
  return server.healthKey === "healthy"
    ? "No active health condition. Resource Usage remains available for comparison."
    : "The server remains observable but needs Lab Administrator attention. Operational details are restricted.";
}

function render() {
  const app = document.querySelector("#app");
  app.innerHTML = state.variant === "A" ? variantA() : state.variant === "B" ? variantB() : variantC();
  renderControls();
  bindServerSelection();
  document.title = `${state.variant} — ${variantNames[state.variant]} · Lab Server Health`;
}

function renderControls() {
  const controls = document.querySelector("#prototype-controls");
  const shouldShow =
    ["localhost", "127.0.0.1", ""].includes(window.location.hostname) ||
    readParam("prototype", "0") === "1";
  controls.hidden = !shouldShow;
  controls.innerHTML = `
    <button class="arrow" type="button" data-direction="-1" aria-label="Previous variant">←</button>
    <span class="prototype-label">${state.variant} — ${variantNames[state.variant]}</span>
    <div class="role-switch" aria-label="Role">
      <button type="button" data-role="user" class="${state.role === "user" ? "active" : ""}">Lab User</button>
      <button type="button" data-role="admin" class="${state.role === "admin" ? "active" : ""}">Lab Admin</button>
    </div>
    <button class="arrow" type="button" data-direction="1" aria-label="Next variant">→</button>
  `;
  controls.querySelectorAll("[data-direction]").forEach((button) => {
    button.addEventListener("click", () => cycleVariant(Number(button.dataset.direction)));
  });
  controls.querySelectorAll("[data-role]").forEach((button) => {
    button.addEventListener("click", () => {
      state.role = button.dataset.role;
      updateUrl({ role: state.role });
      render();
    });
  });
}

function bindServerSelection() {
  document.querySelectorAll("[data-server]").forEach((element) => {
    element.addEventListener("click", () => {
      state.selected = element.dataset.server;
      updateUrl({ server: state.selected });
      render();
    });
  });
}

function cycleVariant(direction) {
  const keys = Object.keys(variantNames);
  const current = keys.indexOf(state.variant);
  state.variant = keys[(current + direction + keys.length) % keys.length];
  updateUrl({ variant: state.variant });
  render();
}

document.addEventListener("keydown", (event) => {
  const target = event.target;
  const isEditing =
    target.matches("input, textarea, [contenteditable='true']") ||
    target.closest("input, textarea, [contenteditable='true']");
  if (isEditing) return;
  if (event.key === "ArrowLeft") cycleVariant(-1);
  if (event.key === "ArrowRight") cycleVariant(1);
});

window.addEventListener("popstate", () => {
  state.variant = readParam("variant", "A").toUpperCase();
  state.role = readParam("role", "user").toLowerCase();
  state.selected = readParam("server", servers[0].id);
  render();
});

render();
