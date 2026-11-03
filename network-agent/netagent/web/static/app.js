// NetAgent app (vanilla JS, no build step)
const $ = (sel) => document.querySelector(sel);
const STORE_KEY = "na.chat.v1";
const THEME_KEY = "na.theme";
const MAX_STORED = 200;

const state = {
  messages: [],
  attachments: [],
  busy: false,
  installPrompt: null,
  view: "chat",
  devFilter: "all",
  devSearch: "",
  overview: null,
};

// Layout: two panes (chat + network) on wide screens such as a Z Fold unfolded,
// or when a Fold in Flex mode reports two side-by-side viewport segments.
const MQ_WIDE = matchMedia("(min-width: 680px) and (min-height: 500px)");
const MQ_SEG_SIDE = matchMedia("(horizontal-viewport-segments: 2)");
const MQ_SEG_STACK = matchMedia("(vertical-viewport-segments: 2)");

function isTwoPane() {
  return (MQ_WIDE.matches || MQ_SEG_SIDE.matches) && !MQ_SEG_STACK.matches;
}

const VIEW_TITLES = {
  chat: ["NetAgent", "AI ქსელის ასისტენტი"],
  dash: ["ქსელი", "მოწყობილობები და მოვლენები"],
  settings: ["პარამეტრები", "აპი და ანგარიში"],
};

// ---------------------------------------------------------------- small helpers

function icon(name, cls = "") {
  return `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

let toastTimer;
function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

// ---------------------------------------------------------------- theme

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "light" || mode === "dark") root.dataset.theme = mode;
  else delete root.dataset.theme;
  document.querySelectorAll("#theme button").forEach((b) => b.classList.toggle("on", b.dataset.theme === (mode || "auto")));
  const dark = mode === "dark" || (mode !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute("content", dark ? "#0d1117" : "#f6f7f9"));
}

function loadTheme() {
  let mode = "auto";
  try { mode = localStorage.getItem(THEME_KEY) || "auto"; } catch { /* storage unavailable */ }
  applyTheme(mode);
}

// ---------------------------------------------------------------- API

async function api(path, { method = "GET", json, form } = {}) {
  const headers = { "X-NetAgent": "1" };
  let body;
  if (json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  } else if (form) {
    body = form;
  }
  const res = await fetch(path, { method, headers, body, credentials: "same-origin" });
  if (res.status === 401 && path !== "/api/login") {
    showLogin(await fetch("/api/me").then((r) => r.json()).catch(() => ({})));
    throw new Error("unauthorized");
  }
  return res;
}

async function apiJson(path, opts) {
  const res = await api(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ---------------------------------------------------------------- Markdown (safe subset)

function inline(s) {
  return esc(s)
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])_([^_\n]+)_(?=[\s).,!?]|$)/g, "$1<em>$2</em>");
}

const COPY_LABEL = `${icon("copy")}<span>კოპირება</span>`;
const COPY_BTN = `<button type="button" class="copy" aria-label="კოპირება">${COPY_LABEL}</button>`;

function md(text) {
  const lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  const isTableSep = (l) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l);
  const cells = (l) => l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
  const isList = (l) => /^\s*([-*•]|\d+[.)])\s+/.test(l);
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line.trim())) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) buf.push(lines[i++]);
      i++;
      out.push(`<div class="code"><div class="code-head"><span>output</span>${COPY_BTN}</div><pre><code>${esc(buf.join("\n"))}</code></pre></div>`);
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(cells(lines[i++]));
      out.push(`<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join("")}</tr></thead><tbody>${rows
        .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
      continue;
    }
    const h = line.match(/^#{1,6}\s+(.*)/);
    if (h) { out.push(`<h4>${inline(h[1])}</h4>`); i++; continue; }
    if (isList(line)) {
      const ordered = /^\s*\d+[.)]/.test(line);
      const items = [];
      while (i < lines.length && isList(lines[i])) items.push(lines[i++].replace(/^\s*([-*•]|\d+[.)])\s+/, ""));
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>${items.map((it) => `<li>${inline(it)}</li>`).join("")}</${tag}>`);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^```/.test(lines[i].trim()) && !/^#{1,6}\s/.test(lines[i])
           && !isList(lines[i]) && !(lines[i].includes("|") && isTableSep(lines[i + 1] || ""))) {
      para.push(inline(lines[i++]));
    }
    out.push(`<p>${para.join("<br>")}</p>`);
  }
  return out.join("");
}

// ---------------------------------------------------------------- chat storage & rendering

function save() {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(state.messages.slice(-MAX_STORED))); } catch { /* full or disabled */ }
}

function load() {
  try { state.messages = JSON.parse(localStorage.getItem(STORE_KEY) || "[]"); } catch { state.messages = []; }
}

function timeLabel(ts) {
  return new Date(ts).toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit" });
}

function fileUrl(name, download = false) {
  return `/api/files/${encodeURIComponent(name)}${download ? "?download=1" : ""}`;
}

function fileCard(name) {
  const kind = /\.xlsx$/i.test(name) ? ["table", "green", "Excel ფაილი"] : /\.png$/i.test(name) ? ["image", "blue", "სურათი"] : ["file", "blue", "ტექსტური ფაილი"];
  const a = el("a", "file-card", `<span class="file-ico ${kind[1]}">${icon(kind[0])}</span>
    <span class="file-meta"><span class="file-name"></span><span class="file-sub">${kind[2]} · ჩამოტვირთვა</span></span>${icon("download")}`);
  a.href = fileUrl(name, true);
  a.querySelector(".file-name").textContent = name;
  return a;
}

function renderMessage(m) {
  const box = el("div", `msg ${m.role}`);
  if (m.role === "user") {
    if (m.thumbs?.length) {
      const t = el("div", "thumbs");
      for (const src of m.thumbs) { const img = el("img"); img.src = src; img.alt = ""; t.appendChild(img); }
      box.appendChild(t);
    }
    if (m.files?.length) {
      const f = el("div", "attached", icon("file"));
      f.appendChild(document.createTextNode(m.files.join(", ")));
      box.appendChild(f);
    }
    if (m.text) box.appendChild(document.createTextNode(m.text));
  } else {
    const body = el("div", "md", md(m.text));
    box.appendChild(body);
    if (body.querySelector("table, .code") || m.image) box.classList.add("wide");
    if (m.image) {
      const img = el("img", "result");
      img.src = fileUrl(m.image);
      img.alt = m.text || "chart";
      img.loading = "lazy";
      box.appendChild(img);
    }
    for (const name of m.files || []) box.appendChild(fileCard(name));
    if (m.buttons?.length) {
      const b = el("div", "buttons");
      for (const btn of m.buttons) {
        const x = el("button");
        x.type = "button";
        x.textContent = btn.label;
        x.addEventListener("click", () => send(btn.command));
        b.appendChild(x);
      }
      box.appendChild(b);
    }
  }
  box.appendChild(el("div", "meta", esc(timeLabel(m.ts))));
  return box;
}

const SUGGESTIONS = [
  ["pulse", "blue", "როგორაა ქსელი? რომელიმე მოწყობილობა ხომ არ არის გათიშული?"],
  ["server", "green", "R1-ის ინტერფეისების IP-ები მაჩვენე"],
  ["search", "violet", "რომელი IP-ებია თავისუფალი 192.168.1.0/24-ში?"],
  ["shield", "amber", "რამდენად უსაფრთხოა ქსელი?"],
];

function renderAll() {
  const box = $("#messages");
  box.replaceChildren();
  if (!state.messages.length) {
    const e = el("div", "empty", `<img src="/static/icon-192.png" alt="" width="64" height="64" class="empty-logo">
      <h3>გამარჯობა 👋</h3><p>მკითხე რამე ქსელზე, გამომიგზავნე ფოტო ან config ფაილი.</p>`);
    const grid = el("div", "suggestions");
    for (const [ico, color, q] of SUGGESTIONS) {
      const b = el("button", "suggestion", `<span class="s-ico ${color}">${icon(ico)}</span><span></span>`);
      b.type = "button";
      b.lastElementChild.textContent = q;
      b.addEventListener("click", () => send(q));
      grid.appendChild(b);
    }
    e.appendChild(grid);
    box.appendChild(e);
    return;
  }
  for (const m of state.messages) box.appendChild(renderMessage(m));
  scrollDown();
}

function scrollDown() {
  const box = $("#messages");
  requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
}

function addMessage(m) {
  m.ts = m.ts || Date.now();
  if (!state.messages.length) $("#messages").replaceChildren();
  state.messages.push(m);
  $("#messages").appendChild(renderMessage(m));
  save();
  scrollDown();
}

function pendingBubble(title = "ვფიქრობ...") {
  const box = el("div", "msg bot", `<div class="activity"><div class="activity-head"><span class="spinner"></span><span class="ah-text"></span></div><ul class="steps"></ul></div>`);
  box.querySelector(".ah-text").textContent = title;
  if (!state.messages.length) $("#messages").replaceChildren();
  $("#messages").appendChild(box);
  scrollDown();
  return {
    step(label) {
      box.querySelector(".ah-text").textContent = "ვამუშავებ...";
      const ul = box.querySelector(".steps");
      ul.querySelectorAll("li .spinner").forEach((s) => s.outerHTML = icon("check"));
      const li = el("li", "", `<span class="spinner"></span><span></span>`);
      li.lastElementChild.textContent = label;
      ul.appendChild(li);
      scrollDown();
    },
    remove() { box.remove(); if (!state.messages.length) renderAll(); },
  };
}

// ---------------------------------------------------------------- sending

async function readSSE(res, onEvent) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      let event = "message";
      const data = [];
      for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      if (data.length) onEvent(event, JSON.parse(data.join("\n")));
    }
  }
}

function updateSend() {
  $("#send").disabled = state.busy || (!$("#input").value.trim() && !state.attachments.length);
}

function setBusy(b) {
  state.busy = b;
  updateSend();
}

async function send(text) {
  text = (text ?? "").trim();
  const files = state.attachments.slice();
  if ((!text && !files.length) || state.busy) return;
  switchView("chat");
  setBusy(true);
  addMessage({
    role: "user", text,
    thumbs: files.filter((f) => f.preview).map((f) => f.preview),
    files: files.filter((f) => !f.preview).map((f) => f.file.name),
  });
  state.attachments = [];
  renderAttachments();
  try {
    if (text.startsWith("/") && !files.length && (await runCommand(text))) return;
    await sendChat(text, files);
  } finally {
    setBusy(false);
  }
}

// Deterministic command (no AI). Returns false when the server does not know the command.
async function runCommand(line) {
  const pending = pendingBubble("ვასრულებ...");
  try {
    const res = await api("/api/command", { method: "POST", json: { line } });
    const data = await res.json().catch(() => ({}));
    pending.remove();
    if (res.status === 400) return false;
    addMessage({ role: "bot", text: data.text || data.error || "", files: data.files, image: data.image, buttons: data.buttons });
    if (/^\/(mute|unmute|discover-add)/.test(line)) loadOverview();
  } catch (err) {
    pending.remove();
    if (err.message !== "unauthorized") addMessage({ role: "bot", text: `⚠️ ${err.message}` });
  }
  return true;
}

async function sendChat(text, files) {
  const pending = pendingBubble();
  const form = new FormData();
  form.append("text", text);
  for (const f of files) form.append("files", f.file, f.file.name);
  try {
    const res = await api("/api/chat", { method: "POST", form });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    let answered = false;
    await readSSE(res, (event, data) => {
      if (event === "step") pending.step(data.label);
      if (event === "answer") {
        answered = true;
        pending.remove();
        addMessage({ role: "bot", text: data.text, files: data.files });
      }
    });
    if (!answered) throw new Error("კავშირი გაწყდა — სცადე თავიდან");
  } catch (err) {
    pending.remove();
    if (err.message !== "unauthorized") addMessage({ role: "bot", text: `⚠️ ${err.message}` });
  }
}

// ---------------------------------------------------------------- attachments

function renderAttachments() {
  const box = $("#attachments");
  box.replaceChildren();
  state.attachments.forEach((a, idx) => {
    const chip = el("span", "att");
    if (a.preview) { const img = el("img"); img.src = a.preview; img.alt = ""; chip.appendChild(img); }
    else chip.appendChild(el("span", "att-file", icon("file")));
    const name = el("span", "att-name");
    name.textContent = a.file.name;
    chip.appendChild(name);
    const x = el("button", "att-x", icon("x"));
    x.type = "button";
    x.setAttribute("aria-label", "წაშლა");
    x.addEventListener("click", () => { state.attachments.splice(idx, 1); renderAttachments(); });
    chip.appendChild(x);
    box.appendChild(chip);
  });
  updateSend();
}

async function shrinkImage(file) {
  // Phone photos are large: resize to max 1600px JPEG so uploads are fast and fit the API limit.
  const bitmap = await createImageBitmap(file).catch(() => null);
  if (!bitmap) return file;
  const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
  if (scale === 1 && file.size < 1.5e6) return file;
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.85));
  return new File([blob], file.name.replace(/\.\w+$/, "") + ".jpg", { type: "image/jpeg" });
}

async function addFiles(list) {
  for (let file of list) {
    if (state.attachments.length >= 5) { toast("მაქსიმუმ 5 ფაილი"); break; }
    let preview = null;
    if (file.type.startsWith("image/")) {
      file = await shrinkImage(file);
      preview = await new Promise((r) => { const fr = new FileReader(); fr.onload = () => r(fr.result); fr.readAsDataURL(file); });
    }
    state.attachments.push({ file, preview });
  }
  renderAttachments();
}

// ---------------------------------------------------------------- quick actions

const QUICK = [
  ["pulse", "blue", "სტატუსი", "/status"],
  ["report", "violet", "რეპორტი", "/report"],
  ["shield", "amber", "აუდიტი", "/audit"],
  ["save", "green", "Backup", "/backup"],
  ["server", "blue", "Inventory", "/devices"],
  ["note", "violet", "შენიშვნები", "/notes"],
  ["help", "gray", "ბრძანებები", "/help"],
];

function renderQuick() {
  const chips = $("#quick");
  chips.replaceChildren();
  for (const [ico, , label, cmd] of QUICK) {
    const b = el("button", "chip", `${icon(ico)}<span></span>`);
    b.type = "button";
    b.lastElementChild.textContent = label;
    b.addEventListener("click", () => send(cmd));
    chips.appendChild(b);
  }
  const grid = $("#dash-actions");
  grid.replaceChildren();
  for (const [ico, color, label, cmd] of QUICK.slice(0, 6)) {
    const b = el("button", "action", `<span class="a-ico ${color}">${icon(ico)}</span><span></span>`);
    b.type = "button";
    b.lastElementChild.textContent = label;
    b.addEventListener("click", () => send(cmd));
    grid.appendChild(b);
  }
}

// ---------------------------------------------------------------- dashboard

function ago(ts) {
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60) return "ახლახან";
  if (s < 3600) return `${Math.floor(s / 60)} წთ წინ`;
  if (s < 86400) return `${Math.floor(s / 3600)} სთ წინ`;
  return new Date(ts).toLocaleString("ka-GE", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// Latency sparkline: line in the de-emphasis hue, current value as an accent dot; gaps where down.
function sparkline(values) {
  const pts = values.map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (pts.length < 2) return "";
  const W = 76, H = 24, pad = 3;
  const max = Math.max(...pts.map(([, v]) => v)), min = Math.min(...pts.map(([, v]) => v));
  const span = Math.max(max - min, 0.5);
  const x = (i) => pad + (i / Math.max(values.length - 1, 1)) * (W - 2 * pad);
  const y = (v) => H - pad - ((v - min) / span) * (H - 2 * pad);
  let d = "";
  let pen = false;
  values.forEach((v, i) => {
    if (v == null) { pen = false; return; }
    d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
    pen = true;
  });
  const [li, lv] = pts[pts.length - 1];
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" aria-hidden="true"><path d="${d}"/><circle cx="${x(li).toFixed(1)}" cy="${y(lv).toFixed(1)}" r="2.8"/></svg>`;
}

const EVENT_STYLE = {
  down: ["alert", "red"], up: ["check", "green"], watch: ["pulse", "amber"],
  config: ["note", "violet"], report: ["report", "blue"],
};

function renderDevices() {
  const data = state.overview;
  const box = $("#devices");
  box.replaceChildren();
  if (!data) return;
  if (!data.devices.length) {
    box.appendChild(el("div", "empty-note", "მოწყობილობები ჯერ არ არის.<br>ჩატში დაწერე: <code>/discover 10.0.0.0/24</code>"));
    return;
  }
  const q = state.devSearch.toLowerCase();
  const list = data.devices.filter((d) => (state.devFilter === "all" || !d.up)
    && (!q || `${d.name} ${d.host} ${d.site} ${d.role} ${d.type}`.toLowerCase().includes(q)));
  if (!list.length) {
    box.appendChild(el("div", "empty-note", state.devFilter === "down" ? "✅ ყველა მოწყობილობა ხელმისაწვდომია" : "ვერაფერი მოიძებნა"));
    return;
  }
  for (const d of list) {
    const b = el("button", `device${d.up ? "" : " down"}`);
    b.type = "button";
    const latency = d.up ? (d.latency_ms != null ? `${d.latency_ms < 10 ? d.latency_ms.toFixed(1) : Math.round(d.latency_ms)} ms` : "up") : "";
    b.innerHTML = `<span class="dev-status">${icon(d.up ? "check" : "alert")}</span>
      <span class="dev-main"><span class="dev-name"><span></span>${d.muted ? icon("mute") : ""}${d.watched ? icon("eye") : ""}</span><span class="dev-sub"></span></span>
      <span class="dev-right"><span class="dev-lat"></span>${d.up ? sparkline(d.spark || []) : ""}</span>`;
    b.querySelector(".dev-name span").textContent = d.name;
    // Offline state is spelled out in text, not color alone: "მიუწვდომელი · timeout".
    b.querySelector(".dev-sub").textContent = d.up
      ? [d.host, d.site || d.type].filter(Boolean).join(" · ")
      : ["მიუწვდომელი", d.reason].filter(Boolean).join(" · ");
    b.title = `${d.name} — ${d.host}`;
    b.querySelector(".dev-lat").textContent = latency;
    b.addEventListener("click", () => send(`/health ${d.name}`));
    box.appendChild(b);
  }
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  const down = data.total - data.up;
  const pill = $("#netsum");
  pill.classList.toggle("ok", data.total > 0 && down === 0);
  pill.classList.toggle("bad", down > 0);
  pill.querySelector(".txt").textContent = data.total ? `${data.up}/${data.total}` : "—";
  const badge = $("#tab-badge");
  badge.hidden = down === 0;
  badge.textContent = String(down);

  $("#dash-summary").innerHTML = data.total ? `${data.up}<small> / ${data.total}</small>` : "—";
  const seg = $("#segbar");
  seg.querySelector(".up").style.flexGrow = String(data.up);
  seg.querySelector(".down").style.flexGrow = String(down);
  seg.querySelector(".down").hidden = down === 0;
  const checked = new Date(data.checked_at).toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit" });
  $("#dash-sub").innerHTML = `<span>${down ? `🔴 ${down} მიუწვდომელი` : "🟢 ყველაფერი რიგზეა"}</span><span>განახლდა ${esc(checked)}</span>`;

  const tiles = $("#tiles");
  tiles.replaceChildren();
  const tile = (ico, label, value, sub, bad) => {
    const t = el("div", `tile${bad ? " bad" : ""}`,
      `<div class="tile-label">${icon(ico)}<span></span></div><div class="tile-value"></div><div class="tile-sub"></div>`);
    t.querySelector(".tile-label span").textContent = label;
    t.querySelector(".tile-value").textContent = value;
    t.querySelector(".tile-sub").textContent = sub;
    tiles.appendChild(t);
  };
  tile("alert", "გათიშული", String(down), "ახლა", down > 0);
  tile("bell", "ალერტები", String(data.alerts_24h ?? 0), "ბოლო 24 სთ", false);
  tile("dollar", "AI ხარჯი", `$${data.usage.today.toFixed(2)}`, "დღეს",
    data.usage.budget > 0 && data.usage.today >= data.usage.budget);

  $("#dev-search-wrap").hidden = data.devices.length < 8;
  renderDevices();

  const al = $("#alerts");
  al.replaceChildren();
  if (!data.alerts.length) al.appendChild(el("div", "empty-note", "მოვლენები ჯერ არ ყოფილა."));
  for (const a of data.alerts.slice(0, 20)) {
    const [ico, color] = EVENT_STYLE[a.kind] || ["bell", "gray"];
    const item = el("div", "event", `<span class="ev-ico ${color}">${icon(ico)}</span><div><div class="ev-when"></div><div class="md"></div></div>`);
    item.querySelector(".ev-when").textContent = ago(a.ts);
    item.querySelector(".md").innerHTML = md(a.text);
    al.appendChild(item);
  }
  $("#about").textContent = `NetAgent · მოდელი: ${data.model}`;
}

async function loadOverview() {
  const btn = $("#dash-refresh");
  btn.classList.add("spinning");
  if (!state.overview) {
    $("#devices").replaceChildren(el("div", "skeleton"), el("div", "skeleton"), el("div", "skeleton"));
  }
  try {
    state.overview = await apiJson("/api/overview");
    renderOverview();
  } catch (err) {
    if (err.message !== "unauthorized") $("#netsum .txt").textContent = "⚠️";
  } finally {
    btn.classList.remove("spinning");
  }
}

// ---------------------------------------------------------------- push notifications

function urlB64ToUint8Array(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

async function pushState() {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) return { supported: false };
  const reg = await navigator.serviceWorker.ready;
  return { supported: true, reg, sub: await reg.pushManager.getSubscription() };
}

async function refreshPushUI() {
  const st = await pushState().catch(() => ({ supported: false }));
  const toggle = $("#push-toggle");
  if (!st.supported) {
    $("#push-status").textContent = "მიუწვდომელია ამ ბრაუზერში (საჭიროა HTTPS, მაგ. Tailscale)";
    toggle.disabled = true;
    $("#push-test").disabled = true;
    return;
  }
  const on = !!st.sub && Notification.permission === "granted";
  toggle.checked = on;
  toggle.disabled = false;
  $("#push-status").textContent = on ? "ჩართულია — ალერტები ამ მოწყობილობაზე მოვა" : "გამორთულია";
  $("#push-test").disabled = !on;
}

async function setPush(enable) {
  const st = await pushState();
  if (!st.supported) return;
  if (!enable && st.sub) {
    await apiJson("/api/push/unsubscribe", { method: "POST", json: { endpoint: st.sub.endpoint } }).catch(() => {});
    await st.sub.unsubscribe();
    toast("შეტყობინებები გამოირთო");
  } else if (enable && !st.sub) {
    const perm = await Notification.requestPermission();
    if (perm !== "granted") {
      toast("ნებართვა არ მოგეცა — ჩართე აპის პარამეტრებში");
    } else {
      const { key } = await apiJson("/api/push/key");
      const sub = await st.reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8Array(key) });
      await apiJson("/api/push/subscribe", { method: "POST", json: sub.toJSON() });
      toast("🔔 შეტყობინებები ჩაირთო");
    }
  }
  await refreshPushUI();
}

// ---------------------------------------------------------------- views & auth

function applyLayout() {
  const two = isTwoPane();
  const app = $("#app");
  app.classList.toggle("two-pane", two);
  app.dataset.view = state.view;
  const sidePane = two && state.view === "chat";
  for (const v of ["chat", "dash", "settings"]) $(`#view-${v}`).hidden = !(v === state.view || (sidePane && v === "dash"));
  const [title, sub] = VIEW_TITLES[state.view];
  $("#view-title").textContent = title;
  $("#view-sub").textContent = sidePane ? "ჩატი და ქსელი ერთად" : sub;
  return sidePane;
}

function switchView(name) {
  state.view = name;
  document.querySelectorAll(".tabbar button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const sidePane = applyLayout();
  if (name === "dash" || (sidePane && !state.overview)) loadOverview();
  if (name === "settings") {
    refreshPushUI();
    apiJson("/api/command", { method: "POST", json: { line: "/usage" } })
      .then((r) => { $("#usage").innerHTML = md(r.text.split("\n").slice(1).join("\n")); })
      .catch(() => {});
  }
  if (name === "chat") scrollDown();
}

function showLogin(info = {}) {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#totp-row").hidden = !info.totp;
  $("#login-setup").hidden = info.configured !== false;
  $("#password").focus();
}

function showApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
  switchView(state.view);
  renderAll();
  loadOverview();
  const cmd = new URLSearchParams(location.search).get("cmd");
  if (cmd) {
    history.replaceState(null, "", "/");
    send(cmd);
  }
}

async function init() {
  loadTheme();
  load();
  renderQuick();
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

  // login
  $("#pw-toggle").addEventListener("click", () => {
    const pw = $("#password");
    pw.type = pw.type === "password" ? "text" : "password";
  });
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login-btn");
    $("#login-error").textContent = "";
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "შესვლა...";
    try {
      const res = await api("/api/login", { method: "POST", json: { password: $("#password").value, totp: $("#totp").value } });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        $("#login-error").textContent = data.error || "შესვლა ვერ მოხერხდა";
        return;
      }
      $("#password").value = "";
      $("#totp").value = "";
      showApp();
    } finally {
      btn.removeAttribute("aria-busy");
      btn.textContent = "შესვლა";
    }
  });

  // composer
  const input = $("#input");
  const autoGrow = () => { input.style.height = "auto"; input.style.height = `${Math.min(input.scrollHeight, 140)}px`; };
  $("#composer").addEventListener("submit", (e) => {
    e.preventDefault();
    const text = input.value;
    input.value = "";
    autoGrow();
    send(text);
  });
  input.addEventListener("input", () => { autoGrow(); updateSend(); });
  input.addEventListener("keydown", (e) => {
    // Enter sends on desktop; on phones the keyboard's send key submits the form.
    if (e.key === "Enter" && !e.shiftKey && !("ontouchstart" in window)) {
      e.preventDefault();
      $("#composer").requestSubmit();
    }
  });
  input.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addFiles(files); }
  });
  $("#file").addEventListener("change", (e) => { addFiles([...e.target.files]); e.target.value = ""; });

  // copy buttons on code blocks (event delegation)
  $("#messages").addEventListener("click", async (e) => {
    const btn = e.target.closest(".copy");
    if (!btn) return;
    try {
      await navigator.clipboard.writeText(btn.closest(".code").querySelector("pre").innerText);
      btn.innerHTML = `${icon("check")}<span>დაკოპირდა</span>`;
      setTimeout(() => { btn.innerHTML = COPY_LABEL; }, 1500);
    } catch {
      toast("კოპირება ვერ მოხერხდა");
    }
  });

  // navigation & dashboard
  document.querySelectorAll(".tabbar button").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#pane-expand").addEventListener("click", () => switchView("dash"));
  // Re-layout when the Fold is opened/closed or rotated.
  for (const mq of [MQ_WIDE, MQ_SEG_SIDE, MQ_SEG_STACK]) mq.addEventListener("change", () => { applyLayout(); scrollDown(); });
  // Short placeholder when the composer is narrow (S23, Fold cover screen, two-pane chat).
  new ResizeObserver(([entry]) => {
    input.placeholder = entry.contentRect.width < 420 ? "მკითხე რამე…" : "მკითხე რამე ან დაწერე /status";
  }).observe($("#composer"));
  // Flex-mode layout needs the top bar height to put the hinge between messages and input.
  new ResizeObserver(([entry]) => {
    document.documentElement.style.setProperty("--topbar-h", `${Math.round(entry.target.getBoundingClientRect().height)}px`);
  }).observe($(".topbar"));
  $("#netsum").addEventListener("click", () => switchView("dash"));
  $("#dash-refresh").addEventListener("click", loadOverview);
  document.querySelectorAll("#dev-filter button").forEach((b) => b.addEventListener("click", () => {
    state.devFilter = b.dataset.filter;
    document.querySelectorAll("#dev-filter button").forEach((x) => x.classList.toggle("on", x === b));
    renderDevices();
  }));
  $("#dev-search").addEventListener("input", (e) => { state.devSearch = e.target.value; renderDevices(); });

  // settings
  $("#push-toggle").addEventListener("change", (e) => setPush(e.target.checked).catch((err) => { toast(err.message); refreshPushUI(); }));
  $("#push-test").addEventListener("click", () => apiJson("/api/push/test", { method: "POST", json: {} })
    .then((r) => toast(r.sent ? "გაიგზავნა — შეამოწმე შეტყობინებები" : "ვერ გაიგზავნა"))
    .catch((e) => toast(e.message)));
  document.querySelectorAll("#theme button").forEach((b) => b.addEventListener("click", () => {
    try { localStorage.setItem(THEME_KEY, b.dataset.theme); } catch { /* ignore */ }
    applyTheme(b.dataset.theme);
  }));
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", loadTheme);
  $("#help").addEventListener("click", () => send("/help"));
  $("#clear-chat").addEventListener("click", async () => {
    if (!confirm("გავასუფთავო საუბარი?")) return;
    await apiJson("/api/reset", { method: "POST", json: {} }).catch(() => {});
    state.messages = [];
    save();
    renderAll();
    toast("საუბარი გასუფთავდა");
    switchView("chat");
  });
  $("#logout").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST", json: {} }).catch(() => {});
    showLogin(await apiJson("/api/me").catch(() => ({})));
  });
  $("#logout-all").addEventListener("click", async () => {
    if (!confirm("გამოვიდე ყველა მოწყობილობიდან?")) return;
    await api("/api/logout", { method: "POST", json: { everywhere: true } }).catch(() => {});
    showLogin(await apiJson("/api/me").catch(() => ({})));
  });

  // install prompt (Android Chrome)
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    state.installPrompt = e;
    $("#install").hidden = false;
  });
  $("#install").addEventListener("click", async () => {
    if (!state.installPrompt) return;
    state.installPrompt.prompt();
    await state.installPrompt.userChoice;
    state.installPrompt = null;
    $("#install").hidden = true;
  });

  navigator.serviceWorker?.addEventListener("message", (e) => { if (e.data?.type === "alert") loadOverview(); });
  setInterval(() => { if (!document.hidden && !$("#app").hidden) loadOverview(); }, 60_000);

  const me = await apiJson("/api/me").catch(() => ({}));
  if (me.authenticated) showApp();
  else showLogin(me);
}

init();
