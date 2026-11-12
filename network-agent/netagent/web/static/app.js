// NetAgent app (vanilla JS, no build step)
import { setLang, startI18n } from "./i18n.js";
const $ = (sel) => document.querySelector(sel);
const STORE_KEY = "na.chat.v1";
const THEME_KEY = "na.theme";
const MAX_STORED = 200;

const state = {
  demoShown: false,
  messages: [],
  attachments: [],
  busy: false,
  installPrompt: null,
  view: "chat",
  devFilter: "all",
  devSearch: "",
  overview: null,
  queue: [],
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
  term: ["ტერმინალი", "read-only ბრძანებები მოწყობილობებზე"],
  live: ["Live Devices", "ვინ არის ქსელში ახლა"],
  hw: ["კომპიუტერი", "დისკები და RAM"],
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

// ---------------------------------------------------------------- motion
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)");

// restart a CSS animation class on an element, and take it off afterwards
function replay(node, cls, ms = 900) {
  if (!node || REDUCED.matches) return;
  node.classList.remove(cls);
  void node.offsetWidth;  // reflow, so the same class animates again
  node.classList.add(cls);
  clearTimeout(node[`_${cls}`]);
  node[`_${cls}`] = setTimeout(() => node.classList.remove(cls), ms);
}

// count a number up/down to its new value (the hero "5/7")
function countTo(node, to, render) {
  const from = Number(node.dataset.n ?? 0);
  node.dataset.n = String(to);
  if (REDUCED.matches || from === to) { node.innerHTML = render(to); return; }
  const t0 = performance.now(), dur = 700;
  node.classList.add("counting");
  // a hidden tab pauses animation frames: make sure the real value is shown anyway
  clearTimeout(node._countDone);
  node._countDone = setTimeout(() => { if (node.dataset.n === String(to)) { node.innerHTML = render(to); node.classList.remove("counting"); } }, dur + 200);
  const tick = (now) => {
    if (node.dataset.n !== String(to)) return;  // a newer value took over
    const k = Math.min(1, (now - t0) / dur);
    const ease = 1 - (1 - k) ** 3;
    node.innerHTML = render(Math.round(from + (to - from) * ease));
    if (k < 1) requestAnimationFrame(tick);
    else node.classList.remove("counting");
  };
  requestAnimationFrame(tick);
}

// ripple where the finger / mouse pressed
const RIPPLE = ".btn, .chip, .action, .tile, .suggestion, .list-row, .segmented button, .round-btn, .comp-btn, .tabbar button";
document.addEventListener("pointerdown", (e) => {
  const b = e.target.closest(RIPPLE);
  if (!b || REDUCED.matches || b.disabled) return;
  const r = b.getBoundingClientRect();
  const size = Math.max(r.width, r.height);
  const dot = document.createElement("span");
  dot.className = "ripple";
  dot.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size / 2}px;top:${e.clientY - r.top - size / 2}px`;
  b.classList.add("rippling");
  b.appendChild(dot);
  setTimeout(() => dot.remove(), 600);
}, { passive: true });

// ---------------------------------------------------------------- theme

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "light" || mode === "dark") root.dataset.theme = mode;
  else delete root.dataset.theme;
  document.querySelectorAll("#theme button").forEach((b) => b.classList.toggle("on", b.dataset.theme === (mode || "auto")));
  const dark = mode === "dark" || (mode !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute("content", dark ? "#0a0f1c" : "#f4f6fa"));
}

function loadTheme() {
  let mode = "auto";
  try { mode = localStorage.getItem(THEME_KEY) || "dark"; } catch { /* storage unavailable */ }
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
        x.addEventListener("click", () => (NEEDS_PIN.test(btn.command) ? askPin(btn.command) : send(btn.command)));
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
    const e = el("div", "empty", `<img src="/static/logo.svg" alt="" width="64" height="64" class="empty-logo">
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

// The change PIN is never shown or kept in the chat history.
const NEEDS_PIN = /^\/(?:approve|undo) \d+$/;
function maskPin(text) {
  return text.replace(/^(\/(?:approve|undo) \d+) \S+/, "$1 ••••••");
}

function askPin(command) {
  const pin = window.prompt("PIN ცვლილების დასადასტურებლად:");
  if (pin && /^\d{4,12}$/.test(pin.trim())) send(`${command} ${pin.trim()}`);
}

const MAX_QUEUE = 5;

async function send(text) {
  text = (text ?? "").trim();
  const files = state.attachments.slice();
  if (!text && !files.length) return;
  if (state.busy) {
    // A command is still running: a click on a quick action / button (or Enter in the composer, which has
    // already cleared the input) used to be dropped silently. Queue it and run it next instead.
    if (files.length || state.queue.length >= MAX_QUEUE) { toast("მოიცადე — წინა ბრძანება ჯერ სრულდება"); return; }
    state.queue.push(text);
    toast(`რიგშია: ${text.length > 40 ? `${text.slice(0, 40)}…` : text}`);
    return;
  }
  switchView("chat");
  setBusy(true);
  addMessage({
    role: "user", text: maskPin(text),
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
    if (state.queue.length) send(state.queue.shift());
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
        addMessage({ role: "bot", text: data.text, files: data.files, buttons: data.buttons });
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

// ---------------------------------------------------------------- voice input

// Speech-to-text in the browser (Chrome on Android/desktop). Georgian first; text lands in the
// input box so it can be checked before sending.
function setupVoice() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  const btn = $("#mic");
  if (!SR || !btn) return;
  btn.hidden = false;
  let rec = null;
  btn.addEventListener("click", () => {
    if (rec) { rec.stop(); return; }
    const input = $("#input");
    const base = input.value.trim() ? `${input.value.trimEnd()} ` : "";
    rec = new SR();
    rec.lang = "ka-GE";
    rec.interimResults = true;
    rec.continuous = false;
    rec.onresult = (e) => {
      let text = "";
      for (const r of e.results) text += r[0].transcript;
      input.value = base + text;
      input.dispatchEvent(new Event("input"));
    };
    rec.onerror = (e) => {
      if (e.error === "not-allowed" || e.error === "service-not-allowed") toast("მიკროფონზე წვდომა არ არის დაშვებული");
      else if (e.error !== "aborted" && e.error !== "no-speech") toast("ხმის ამოცნობა ვერ მოხერხდა");
    };
    rec.onend = () => { rec = null; btn.classList.remove("listening"); input.focus(); };
    btn.classList.add("listening");
    try { rec.start(); } catch { rec = null; btn.classList.remove("listening"); }
  });
}

// ---------------------------------------------------------------- quick actions

const QUICK = [
  ["pulse", "blue", "სტატუსი", "/status"],
  ["sparkle", "green", "დიაგნოსტიკა", "/diagnose"],
  ["network", "green", "ინტერნეტი", "/isp"],
  ["search", "violet", "ქსელის სკანი", "/scan"],
  ["file", "blue", "ჟურნალი", "/activity"],
  ["report", "violet", "რეპორტი", "/report"],
  ["shield", "amber", "აუდიტი", "/audit"],
  ["lock", "red", "დაცვა", "/security"],
  ["sparkle", "green", "ქსელის ქულა", "/score"],
  ["radar", "blue", "Wi-Fi არხები", "/wifiscan"],
  ["radar", "violet", "Wi-Fi ოთახებში", "/rooms"],
  ["alert", "red", "Wi-Fi გაწყვეტები", "/wifidrops"],
  ["pulse", "green", "ვინ ჭამს ინტერნეტს", "/bandwidth"],
  ["shield", "red", "ყალბი Wi-Fi", "/eviltwin"],
  ["pulse", "amber", "Bufferbloat", "/bufferbloat"],
  ["network", "violet", "სერვისები", "/services"],
  ["shield", "green", "DNS ბლოკი", "/dns"],
  ["sparkle", "amber", "დილის შეჯამება", "/morning"],
  ["server", "gray", "Home Assistant", "/mqtt"],
  ["help", "amber", "Runbook", "/runbook"],
  ["save", "green", "Backup", "/backup"],
  ["server", "blue", "Inventory", "/devices"],
  ["sparkle", "violet", "ქვიზი", "/quiz"],
  ["network", "blue", "რუკა", "/map"],
  ["file", "gray", "ლოგები", "/logs"],
  ["note", "violet", "შენიშვნები", "/notes"],
  ["help", "gray", "ბრძანებები", "/help"],
];

// Demo mode (python -m netagent demo): failure scenarios one tap away.
const DEMO_ACTION = ["sparkle", "violet", "დემო სცენარები", "/demo"];

function renderQuick(demo = false) {
  const actions = demo ? [DEMO_ACTION, ...QUICK] : QUICK;
  const chips = $("#quick");
  chips.replaceChildren();
  for (const [ico, , label, cmd] of actions) {
    const b = el("button", "chip", `${icon(ico)}<span></span>`);
    b.type = "button";
    b.lastElementChild.textContent = label;
    b.addEventListener("click", () => send(cmd));
    chips.appendChild(b);
  }
  const grid = $("#dash-actions");
  grid.replaceChildren();
  for (const [ico, color, label, cmd] of actions.filter((q) => q[3] !== "/help").slice(0, 6)) {
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
  config: ["note", "violet"], report: ["report", "blue"], syslog: ["file", "amber"], newdevice: ["search", "violet"],
  isp: ["network", "blue"], site: ["network", "violet"], escalation: ["bell", "red"], scheduled: ["report", "gray"],
  diagnosis: ["sparkle", "blue"], security: ["lock", "red"], presence: ["eye", "gray"],
};

function renderDevices() {
  const data = state.overview;
  const box = $("#devices");
  box.replaceChildren();
  if (!data) return;
  if (!data.devices.length) {
    box.appendChild(el("div", "empty-note", "<span>მართვადი მოწყობილობები ჯერ არ არის.</span><br><span>როცა როუტერს ან switch-ს ქსელში შეაერთებ, თავისით ამოვიცნობ და აქ გამოჩნდება.</span>"));
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

  if (data.total) countTo($("#dash-summary"), data.up, (n) => `${n}<small>/${data.total}</small>`);
  else $("#dash-summary").innerHTML = "—";
  // ring gauge: cyan arc = reachable share, red arc right after it = unreachable share
  const pct = data.total ? Math.round((100 * data.up) / data.total) : 0;
  const gap = data.up && down ? 2 : 0;
  $("#ring-up").style.strokeDasharray = `${Math.max(pct - gap, 0)} 100`;
  $("#ring-down").style.strokeDasharray = `${down ? Math.max(100 - pct - gap, 0) : 0} 100`;
  $("#ring-down").style.strokeDashoffset = `${-pct}`;
  const health = $("#hero-health");
  health.textContent = data.total ? `${pct}% ჯანმრთელი` : "მოწყობილობები ჯერ არ არის";
  health.classList.toggle("bad", down > 0);
  const checked = new Date(data.checked_at).toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit" });
  $("#dash-sub").innerHTML = `<span class="${down ? "sub-bad" : "sub-ok"}">${down ? `${down} გათიშულია` : "ყველაფერი რიგზეა"}</span><span>განახლდა ${esc(checked)}</span>`;

  const tiles = $("#tiles");
  tiles.classList.toggle("no-anim", tiles.childElementCount > 0);  // the cards fly in once, not on every refresh
  tiles.replaceChildren();
  const tile = (ico, label, value, sub, tone, cmd) => {
    const t = el("button", `tile${tone ? ` ${tone}` : ""}`,
      `<div class="tile-label">${icon(ico)}<span></span></div><div class="tile-value"></div><div class="tile-sub"></div>`);
    t.type = "button";
    t.querySelector(".tile-label span").textContent = label;
    t.querySelector(".tile-value").textContent = value;
    t.querySelector(".tile-sub").textContent = sub;
    if (cmd) t.addEventListener("click", () => send(cmd));
    tiles.appendChild(t);
  };
  const isp = data.isp, sec = data.security;
  tile("network", "ინტერნეტი", isp?.down_now ? "გათიშ." : isp?.uptime != null ? `${isp.uptime}%` : "—", "24 სთ",
    isp?.down_now ? "bad" : isp ? "good" : "", "/isp");
  tile("pulse", "ping", isp?.latency != null ? `${Math.round(isp.latency)} ms` : "—", "ახლა",
    isp?.latency > 100 ? "warn" : "", "/diagnose ინტერნეტი ნელია");
  tile("shield", "დაცვა", !sec ? "—" : sec.ok ? "OK" : String(sec.findings_24h), sec && !sec.ok ? "მიგნება 24 სთ" : "ARP · DHCP",
    !sec ? "" : sec.ok ? "good" : "bad", "/security");
  tile("bell", "ალერტები", String(data.alerts_24h ?? 0), "24 სთ", data.alerts_24h ? "warn" : "", "/activity");

  renderIsp(data.isp);
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
  if (Boolean(data.demo) !== state.demoShown) {
    state.demoShown = Boolean(data.demo);
    renderQuick(state.demoShown);
  }
}

// Internet card: uptime, last speed test and a latency line with outage marks (24 h).
function renderIsp(isp) {
  const card = $("#isp-card");
  if (!isp || !isp.points?.length) { card.hidden = true; return; }
  card.hidden = false;
  card.classList.toggle("bad", Boolean(isp.down_now));
  const W = 300, H = 46, pts = isp.points;
  const vals = pts.map((p) => p[1]).filter((v) => v != null);
  const max = Math.max(...vals, 1), min = Math.min(...vals, 0);
  const x = (i) => (i / Math.max(pts.length - 1, 1)) * W;
  const y = (v) => H - 3 - ((v - min) / Math.max(max - min, 1)) * (H - 6);
  let d = "", pen = false, gaps = "";
  pts.forEach((p, i) => {
    if (p[1] == null) { pen = false; gaps += `<rect x="${x(i).toFixed(1)}" y="0" width="${Math.max(W / pts.length, 2).toFixed(1)}" height="${H}"/>`; return; }
    d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`;
    pen = true;
  });
  const speed = isp.last_speed ? `ჩამოტვირთვა ${isp.last_speed.down_mbps} · ატვირთვა ${isp.last_speed.up_mbps ?? "—"} Mbps` : "სიჩქარე: /speedtest";
  card.innerHTML = `<div class="isp-title">${icon("network")}<span>ინტერნეტი</span></div>
    <div class="isp-big"></div><svg class="isp-chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${gaps}<path d="${d}" pathLength="1"${card.dataset.drawn ? "" : ' class="draw"'}/></svg>
    <div class="isp-sub"></div>`;
  card.querySelector(".isp-big").textContent = isp.down_now ? "🔴 არ არის" : `${isp.uptime ?? "—"}%`;
  card.querySelector(".isp-sub").textContent = `${isp.latency != null ? `${isp.latency} ms` : ""} · გათიშვები 24 სთ: ${isp.outages} · ${speed}`;
  card.dataset.drawn = "1";
  card.onclick = () => send("/isp");
}

// ---------------------------------------------------------------- Wi-Fi room by room (phone -> this PC)

function roomsProgress(pct, text) {
  const box = $("#rooms-progress");
  box.hidden = pct == null;
  if (pct == null) return;
  box.querySelector(".rp-bar span").style.width = `${pct}%`;
  box.querySelector(".rp-text").textContent = text;
}

async function lanPing(n = 12) {
  const xs = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await api(`/api/lantest/ping?r=${Math.random()}`);
    xs.push(performance.now() - t0);
  }
  xs.shift();  // the first one also opens the connection
  const sorted = [...xs].sort((a, b) => a - b);
  const jitter = xs.slice(1).reduce((s, x, i) => s + Math.abs(x - xs[i]), 0) / Math.max(xs.length - 1, 1);
  return { ping: sorted[Math.floor(sorted.length / 2)], jitter };
}

async function lanDown(seconds = 6, onProgress) {
  const ctrl = new AbortController();
  const res = await fetch(`/api/lantest/down?mb=64&r=${Math.random()}`, { signal: ctrl.signal, credentials: "same-origin" });
  const reader = res.body.getReader();
  let bytes = 0, t0 = 0;
  const start = performance.now();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!t0) { t0 = performance.now(); continue; }  // start the clock at the first chunk
      bytes += value.length;
      const el = (performance.now() - t0) / 1000;
      onProgress?.(Math.min(1, (performance.now() - start) / 1000 / seconds), (bytes * 8) / el / 1e6);
      if (el > seconds) break;
    }
  } finally {
    ctrl.abort();
  }
  return (bytes * 8) / Math.max((performance.now() - t0) / 1000, 0.001) / 1e6;
}

async function lanUp(seconds = 5, onProgress) {
  const chunk = new Uint8Array(4 * 1024 * 1024);
  crypto.getRandomValues(chunk.subarray(0, 65536));
  let bytes = 0;
  const t0 = performance.now();
  while ((performance.now() - t0) / 1000 < seconds) {
    await fetch("/api/lantest/up", { method: "POST", body: chunk, headers: { "X-NetAgent": "1" }, credentials: "same-origin" });
    bytes += chunk.length;
    const el = (performance.now() - t0) / 1000;
    onProgress?.(Math.min(1, el / seconds), (bytes * 8) / el / 1e6);
  }
  return (bytes * 8) / ((performance.now() - t0) / 1000) / 1e6;
}

async function measureRoom(room) {
  const btn = $("#room-go");
  btn.disabled = true;
  try {
    roomsProgress(3, "ping...");
    const { ping, jitter } = await lanPing();
    const down = await lanDown(6, (k, mbps) => roomsProgress(5 + k * 55, `ჩამოტვირთვა (download): ${mbps.toFixed(0)} Mbps`));
    const up = await lanUp(5, (k, mbps) => roomsProgress(60 + k * 38, `ატვირთვა (upload): ${mbps.toFixed(0)} Mbps`));
    roomsProgress(100, "ვინახავ...");
    await apiJson("/api/rooms", { method: "POST", json: { room, down, up, ping, jitter } });
    toast(`📍 ${room}: ${down.toFixed(0)} Mbps`);
    await loadRooms(room);
  } catch (err) {
    toast(`გაზომვა ვერ მოხერხდა: ${err.message}`);
  } finally {
    btn.disabled = false;
    setTimeout(() => roomsProgress(null), 600);
  }
}

const ROOM_TONE = (r) => (r.down == null ? "bad" : r.down >= 40 && (r.ping ?? 0) < 30 ? "good" : r.down >= 15 ? "warn" : "bad");

async function loadRooms(highlight = "") {
  let data;
  try { data = await apiJson("/api/rooms"); } catch { return; }
  const list = $("#rooms-list");
  list.replaceChildren();
  $("#room-names").replaceChildren(...data.rooms.map((r) => Object.assign(el("option"), { value: r.room })));
  const local = ["127.0.0.1", "localhost", "::1"].includes(location.hostname);
  if (local) list.appendChild(Object.assign(el("div", "rooms-note"), { textContent: "ეს გვერდი ამავე კომპიუტერზეა გახსნილი — Wi-Fi-ის გასაზომად ტელეფონიდან გახსენი აპი." }));
  const best = Math.max(1, ...data.rooms.map((r) => r.down || 0));
  for (const r of data.rooms) {
    const row = el("div", `room-row ${ROOM_TONE(r)}${r.room === highlight ? " is-new" : ""}`,
      `<div class="room-top"><span class="room-name"></span><span class="room-val"></span></div>
       <div class="room-bar"><span></span></div><div class="room-sub"></div>`);
    row.querySelector(".room-name").textContent = r.room;
    row.querySelector(".room-val").textContent = r.down != null ? `${Math.round(r.down)} Mbps` : "—";
    row.querySelector(".room-sub").textContent = `ატვირთვა (upload) ${r.up != null ? Math.round(r.up) : "—"} Mbps · ping ${r.ping != null ? r.ping.toFixed(0) : "—"} ms`;
    list.appendChild(row);
    requestAnimationFrame(() => { row.querySelector(".room-bar span").style.width = `${Math.max(3, (100 * (r.down || 0)) / best)}%`; });
    setTimeout(() => { row.querySelector(".room-bar span").style.width = `${Math.max(3, (100 * (r.down || 0)) / best)}%`; }, 300);
  }
  for (const a of data.advice) {
    const n = el("div", "rooms-advice");
    n.innerHTML = inline(a);
    list.appendChild(n);
  }
}

// ---------------------------------------------------------------- Wi-Fi dead zones (grid map + walk mode)

const dz = { map: null, busy: false, walk: null, routerMode: false, advice: null };
const netType = () => navigator.connection?.type || "";  // Android Chrome: "wifi" / "cellular"

// one ping to this PC with a time limit; null = lost
async function pingOnce(limit = 1500) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), limit);
  const t0 = performance.now();
  try {
    const r = await fetch(`/api/lantest/ping?r=${Math.random()}`, { signal: ctrl.signal, credentials: "same-origin", cache: "no-store" });
    return r.ok ? performance.now() - t0 : null;
  } catch { return null; } finally { clearTimeout(timer); }
}

async function quickTest(onStep) {
  const xs = [];
  for (let i = 0; i < 10; i++) { xs.push(await pingOnce(1000)); onStep?.(i / 10 * 0.45); }
  const ok = xs.slice(1).filter((x) => x != null);
  const loss = Math.round((100 * xs.slice(1).filter((x) => x == null).length) / (xs.length - 1));
  const ping = ok.length ? [...ok].sort((a, b) => a - b)[Math.floor(ok.length / 2)] : null;
  let down = null;
  if (loss < 60) {
    try { down = await lanDown(2.5, (k) => onStep?.(0.45 + k * 0.55)); } catch { down = 0; }
  }
  return { ping, loss, down, net: netType() };
}

function dzCellName(r, c) { return `${String.fromCharCode(65 + c)}${r + 1}`; }

function renderDz() {
  const m = dz.map;
  if (!m) return;
  const opts = (sel, v) => { sel.replaceChildren(...[2, 3, 4, 5, 6, 7, 8].map((n) => Object.assign(el("option"), { value: n, textContent: n, selected: n === v }))); };
  opts($("#dz-cols"), m.cols);
  opts($("#dz-rows"), m.rows);
  const grid = $("#dz-grid");
  grid.style.gridTemplateColumns = `repeat(${m.cols}, minmax(0, 1fr))`;
  grid.replaceChildren();
  for (let r = 0; r < m.rows; r++) {
    for (let c = 0; c < m.cols; c++) {
      const cell = m.cells[`${r},${c}`];
      const b = el("button", `dz-cell ${cell ? `c-${cell.class}` : "c-none"}`);
      b.type = "button";
      b.dataset.r = r; b.dataset.c = c;
      b.innerHTML = `<span class="dz-name">${dzCellName(r, c)}</span><span class="dz-val">${cell ? (cell.class === "dead" ? "☠️" : cell.down != null ? Math.round(cell.down) : "·") : ""}</span>`;
      b.title = cell ? `${dzCellName(r, c)}: ${cell.down != null ? `${Math.round(cell.down)} Mbps` : "—"} · ping ${cell.ping != null ? Math.round(cell.ping) : "—"} ms · loss ${cell.loss ?? 0}%` : dzCellName(r, c);
      if (m.router === `${r},${c}`) { b.classList.add("is-router"); b.querySelector(".dz-val").textContent = "📡"; }
      const meshAt = (dz.advice?.mesh || []).find((g) => g.at === dzCellName(r, c));
      if (meshAt) { b.classList.add("is-mesh"); b.title += ` · mesh აქ (${meshAt.for.join(", ")})`; }
      b.addEventListener("click", () => (dz.routerMode ? dzSetRouter(r, c) : dzMeasureCell(r, c, b)));
      grid.appendChild(b);
    }
  }
  const dead = Object.entries(m.cells).filter(([, x]) => x.class === "dead").map(([k]) => dzCellName(...k.split(",").map(Number)));
  const weak = Object.entries(m.cells).filter(([, x]) => x.class === "weak").map(([k]) => dzCellName(...k.split(",").map(Number)));
  const spots = m.spots.filter((s) => s.class === "dead" || s.class === "weak").map((s) => s.name);
  const sum = $("#dz-summary");
  sum.replaceChildren();
  const line = (cls, text) => sum.appendChild(Object.assign(el("div", `dz-line ${cls}`), { textContent: text }));
  if (["127.0.0.1", "localhost", "::1"].includes(location.hostname)) {
    line("note", "ეს გვერდი ამავე კომპიუტერზეა გახსნილი — Wi-Fi-ის გასაზომად ტელეფონიდან გახსენი აპი.");
  }
  if (dead.length) line("dead", `☠️ მკვდარი: ${dead.join(", ")}`);
  if (weak.length) line("weak", `🟠 სუსტი: ${weak.join(", ")}`);
  if (spots.length) line("weak", `📍 მონიშნული ცუდი ადგილები: ${spots.join(", ")}`);
  if (Object.keys(m.cells).length && !dead.length && !weak.length && !spots.length) line("ok", "✅ მკვდარი ზონა ჯერ არ ჩანს");
  const adv = dz.advice || {};
  if (adv.need_router) line("note", "📡 მონიშნე, სად დგას როუტერი („📡 როუტერი“, მერე უჯრა) — გეტყვი, სად დადგა mesh.");
  for (const g of adv.mesh || []) line("mesh", `📶 mesh / repeater → ${g.at} (დაფარავს ${g.for.join(", ")})${g.measured ? "" : " — ეს უჯრა ჯერ გაზომე"}`);
  if (adv.move_router) line("note", `↔️ როუტერი კიდეშია — სჯობს ${adv.move_router}-ის ახლოს`);
  if (dead.length || weak.length || spots.length) {
    const more = el("button", "link-btn");
    more.type = "button";
    more.textContent = "რა ეშველება? → /deadzones";
    more.addEventListener("click", () => { switchView("chat"); send("/deadzones"); });
    sum.appendChild(more);
  }
}

async function loadDz() {
  try { const m = await apiJson("/api/wifimap"); dz.advice = m.advice; dz.map = m; renderDz(); } catch { /* ignore */ }
}

async function dzPost(what, json) {
  const r = await apiJson(`/api/wifimap/${what}`, { method: "POST", json });
  dz.map = r.map;
  dz.advice = r.advice;
  renderDz();
  return r.result;
}

async function dzSetRouter(r, c) {
  dz.routerMode = false;
  $("#dz-router").classList.remove("on");
  try { await dzPost("router", { row: r, col: c }); toast(`📡 როუტერი: ${dzCellName(r, c)}`); } catch (e) { toast(e.message); }
}

async function dzMeasureCell(r, c, btn) {
  if (dz.busy) { toast("მოიცადე — წინა გაზომვა ჯერ მიმდინარეობს"); return; }
  dz.busy = true;
  btn.classList.add("measuring");
  btn.style.setProperty("--p", "0");
  try {
    const res = await quickTest((k) => btn.style.setProperty("--p", String(Math.round(k * 100))));
    const m = await dzPost("cell", { row: r, col: c, ...res });
    toast(`${dzCellName(r, c)}: ${m.class === "dead" ? "☠️ მკვდარი ზონა" : m.down != null ? `${Math.round(m.down)} Mbps` : "—"}`);
    if (m.class === "dead") navigator.vibrate?.([120, 60, 120]);
  } catch (err) {
    toast(`გაზომვა ვერ მოხერხდა: ${err.message}`);
  } finally {
    dz.busy = false;
    btn.classList.remove("measuring");
  }
}

// walk mode: ping twice a second, show quality, buzz when it gets bad
function dzQuality(win) {
  const lost = win.filter((x) => x == null).length;
  const ok = win.filter((x) => x != null);
  const med = ok.length ? [...ok].sort((a, b) => a - b)[Math.floor(ok.length / 2)] : 999;
  const loss = (100 * lost) / Math.max(win.length, 1);
  let q = 100 - loss * 1.5 - Math.max(0, med - 10) * 0.6;
  if (netType() === "cellular") q = 0;
  return { q: Math.max(0, Math.min(100, Math.round(q))), med, loss };
}

function dzWalkRender(w) {
  const { q, med, loss } = dzQuality(w.win);
  const meter = $("#dz-meter");
  const cls = q >= 75 ? "good" : q >= 50 ? "ok" : q >= 25 ? "weak" : "dead";
  meter.className = `dz-meter m-${cls}`;
  meter.style.setProperty("--q", String(q));
  meter.querySelector(".dz-q").textContent = String(q);
  $("#dz-walk-text").textContent = netType() === "cellular" ? "📱 Wi-Fi გაითიშა — ტელეფონი მობილურ ინტერნეტზეა"
    : `ping ${med >= 999 ? "—" : Math.round(med)} ms · დანაკარგი ${Math.round(loss)}%`;
  const hist = w.hist.slice(-60);
  const d = hist.map((v, i) => `${i ? "L" : "M"}${(i / 59) * 120},${30 - (v / 100) * 28 - 1}`).join("");
  $("#dz-spark path").setAttribute("d", d);
  if (cls === "dead" || cls === "weak") {
    w.bad += 1;
    if (w.bad === 3) navigator.vibrate?.(cls === "dead" ? [200, 80, 200, 80, 200] : [150]);
  } else w.bad = 0;
  return { q, med, loss };
}

function dzWalkStart() {
  const w = { win: [], hist: [], bad: 0, on: true, last: null };
  dz.walk = w;
  $("#dz-walk-go").textContent = "გაჩერება";
  $("#dz-mark").disabled = false;
  const step = async () => {
    if (!w.on) return;
    const v = await pingOnce(1200);
    if (!w.on) return;
    w.win = [...w.win.slice(-7), v];  // the last ~4 seconds
    w.last = dzWalkRender(w);
    w.hist.push(w.last.q);
    setTimeout(step, 450);
  };
  step();
}

function dzWalkStop() {
  if (dz.walk) dz.walk.on = false;
  dz.walk = null;
  $("#dz-walk-go").textContent = "დაწყება";
  $("#dz-mark").disabled = true;
}

async function dzMark() {
  const w = dz.walk;
  if (!w?.last) return;
  const name = prompt("ამ ადგილის სახელი (მაგ. აივანი, დერეფანი):", "") ?? "";
  const { med, loss } = w.last;
  try {
    const m = await dzPost("spot", { name, ping: med >= 999 ? null : med, loss, net: netType() });
    toast(`📍 ${m.name}: ${m.class === "dead" ? "☠️ მკვდარი" : m.class === "weak" ? "სუსტი" : "ნორმა"}`);
  } catch (err) { toast(err.message); }
}

// ---------------------------------------------------------------- this PC: disks and RAM

const HW_WORD = { ok: "ჯანმრთელი", warn: "ყურადღება", bad: "პრობლემა" };

function hwRing(pct, status) {
  const v = pct == null ? 100 : pct;
  return `<svg class="hw-ring s-${status}" viewBox="0 0 120 120" aria-hidden="true"><circle class="t" cx="60" cy="60" r="50"/>
    <circle class="v" cx="60" cy="60" r="50" pathLength="100" style="stroke-dasharray:0 100" data-v="${v}"/></svg>`;
}

function hwFact(label, value) {
  return value == null || value === "" ? "" : `<div class="hw-fact"><span>${esc(label)}</span><b>${esc(String(value))}</b></div>`;
}

function renderHw(d) {
  const all = [...d.disks.map((x) => x.status), d.ram.status];
  const worst = all.includes("bad") ? "bad" : all.includes("warn") ? "warn" : "ok";
  $("#hw-overall").className = `hw-overall s-${worst}`;
  $("#hw-overall").innerHTML = `<span class="hw-dot"></span><div><b>${worst === "ok" ? "ყველაფერი ჯანმრთელია" : worst === "warn" ? "ყურადღება სჭირდება" : "პრობლემაა"}</b>
    <small>${d.disks.length} დისკი · RAM ${d.ram.total_gb} GB · ${new Date(d.ts).toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit" })}</small></div>`;

  const disks = $("#hw-disks");
  disks.replaceChildren();
  const pick = $("#ss-disk");
  const was = pick.value;
  pick.replaceChildren(...d.disks.map((x) => Object.assign(el("option"), { value: x.id, textContent: `${x.id}: ${x.name} (${x.size_gb} GB)` })));
  if (was) pick.value = was;
  for (const x of d.disks) {
    const s = x.details || {};
    const card = el("div", `hw-card s-${x.status}`);
    const life = x.life_pct;
    card.innerHTML = `<div class="hw-top">
        <div class="hw-gauge">${hwRing(life, x.status)}<div class="hw-gv"><b>${life == null ? (x.status === "ok" ? "OK" : "!") : `${life}%`}</b><small>${life == null ? "სტატუსი" : "სიცოცხლე"}</small></div></div>
        <div class="hw-main"><div class="hw-name"></div><div class="hw-kind"></div>
          <span class="hw-badge s-${x.status}">${HW_WORD[x.status]}</span></div>
      </div>
      <div class="hw-facts">${hwFact("ტემპერატურა", s.temperature_c != null ? `${s.temperature_c}°C` : null)}
        ${hwFact("ჩართული", s.power_on_hours != null ? `${s.power_on_hours.toLocaleString()} სთ` : null)}
        ${hwFact("ჩაწერილი", s.written_tb != null ? `${s.written_tb} TB` : null)}
        ${hwFact("სათადარიგო ბლოკები", s.spare_pct != null ? `${s.spare_pct}%` : null)}
        ${hwFact("შეცდომები", s.media_errors ?? s.reallocated_sectors ?? null)}
        ${hwFact("უეცარი გათიშვა", s.unsafe_shutdowns || null)}
        ${hwFact("დარჩა (პროგნოზი)", x.forecast?.years_left != null ? `~${x.forecast.years_left} წელი` : null)}</div>
      <div class="hw-why"></div><div class="hw-vols"></div>`;
    card.querySelector(".hw-name").textContent = x.name;
    card.querySelector(".hw-kind").textContent = `${x.kind} · ${x.size_gb} GB`;
    const why = card.querySelector(".hw-why");
    for (const w of x.why) why.appendChild(Object.assign(el("div", "hw-warn"), { textContent: `⚠️ ${w}` }));
    if (!Object.keys(s).length) why.appendChild(Object.assign(el("div", "hw-info"), { textContent: "დეტალური SMART ამ დისკზე Windows-მა ადმინის გარეშე არ მოგვცა — ჩანს Windows-ის სტატუსი." }));
    if (x.forecast?.wait_days) why.appendChild(Object.assign(el("div", "hw-info"), { textContent: `⏳ ცვეთის პროგნოზი ${x.forecast.wait_days} დღეში გამოჩნდება (საჭიროა ერთი კვირის მონაცემი).` }));
    const vols = card.querySelector(".hw-vols");
    for (const v of x.volumes) {
      const row = el("div", "hw-vol", `<div class="hw-vol-top"><b></b><span></span></div><div class="hw-bar"><span></span></div>`);
      row.querySelector("b").textContent = `${v.letter}:${v.label ? ` ${v.label}` : ""}`;
      row.querySelector(".hw-vol-top span").textContent = `${v.free_gb} GB თავისუფალი ${v.size_gb}-დან`;
      row.classList.toggle("full", (v.used_pct || 0) >= 90);
      vols.appendChild(row);
      setTimeout(() => { row.querySelector(".hw-bar span").style.width = `${v.used_pct || 0}%`; }, 60);
    }
    disks.appendChild(card);
  }

  const r = d.ram;
  const ram = $("#hw-ram");
  ram.replaceChildren();
  const card = el("div", `hw-card s-${r.status}`);
  card.innerHTML = `<div class="hw-top">
      <div class="hw-gauge">${hwRing(r.status === "ok" ? 100 : r.status === "warn" ? 60 : 25, r.status)}<div class="hw-gv"><b>${r.status === "ok" ? "OK" : "!"}</b><small>შეცდომები</small></div></div>
      <div class="hw-main"><div class="hw-name">${r.total_gb} GB RAM</div><div class="hw-kind">ახლა გამოყენებულია ${r.used_gb} GB (${Math.round(r.percent)}%)</div>
        <span class="hw-badge s-${r.status}">${HW_WORD[r.status]}</span></div>
    </div>
    <div class="hw-vol ${r.percent >= 90 ? "full" : ""}"><div class="hw-bar"><span></span></div></div>
    <div class="hw-mods"></div><div class="hw-why"></div>`;
  for (const m of r.modules) {
    const row = el("div", "hw-mod");
    row.textContent = `${m.slot}: ${m.size_gb} GB ${m.type}${m.speed ? `-${m.speed}` : ""} · ${m.maker || "?"} ${m.part}`;
    card.querySelector(".hw-mods").appendChild(row);
  }
  for (const w of r.why) card.querySelector(".hw-why").appendChild(Object.assign(el("div", "hw-warn"), { textContent: `⚠️ ${w}` }));
  if (r.diag) {
    const when = new Date(r.diag.ts).toLocaleDateString("ka-GE");
    card.querySelector(".hw-why").appendChild(Object.assign(el("div", r.diag.id === 1202 ? "hw-warn" : "hw-info"), {
      textContent: r.diag.id === 1202 ? `🔴 Windows Memory Diagnostic (${when}): შეცდომა იპოვა` : `✅ Windows Memory Diagnostic (${when}): შეცდომა არ არის`,
    }));
  }
  card.querySelector(".hw-why").appendChild(Object.assign(el("div", "hw-info"), {
    textContent: r.whea_30d ? `აპარატურული შეცდომები 30 დღეში: ${r.whea_30d}` : "✅ აპარატურული შეცდომა ბოლო 30 დღეში არ ყოფილა",
  }));
  ram.appendChild(card);
  setTimeout(() => { card.querySelector(".hw-bar span").style.width = `${r.percent}%`; }, 60);
  // the rings fill up
  setTimeout(() => document.querySelectorAll("#view-hw .hw-ring .v").forEach((c) => { c.style.strokeDasharray = `${c.dataset.v} 100`; }), 80);
}

async function loadHw(refresh = false) {
  const btn = $("#hw-refresh");
  btn.classList.add("spinning");
  try {
    renderHw(await apiJson(`/api/hw${refresh ? "?refresh=1" : ""}`));
  } catch (err) {
    if (err.message !== "unauthorized") $("#hw-disks").replaceChildren(Object.assign(el("div", "empty-note"), { textContent: `⚠️ ${err.message}` }));
  } finally {
    btn.classList.remove("spinning");
  }
}

// ---------------------------------------------------------------- RAM test (inside Windows)

let mtTimer = null;
const MT_TEST = { "0x00…": "ნულები", "0xFF…": "ერთიანები", "0x55…": "ჭადრაკი", "0xAA…": "ჭადრაკი (შებრუნებული)",
  "own address": "საკუთარი მისამართი", "inverted address": "შებრუნებული მისამართი", "random": "შემთხვევითი",
  "moving inversions ↑": "მოძრავი ინვერსია ↑", "moving inversions ↓": "მოძრავი ინვერსია ↓" };

function mtTestName(n) {
  if (!n) return "";
  if (n.startsWith("walking 1")) return `მოძრავი ბიტი ${n.split("bit ")[1] ?? ""}`;
  return MT_TEST[n] || n;
}

function renderMemtest(st) {
  const running = st.status === "starting" || st.status === "running";
  $("#mt-run").hidden = !running;
  $("#mt-stop").hidden = !running;
  $("#mt-quick").disabled = running;
  $("#mt-full").disabled = running;
  const badge = $("#mt-badge");
  const res = $("#mt-result");
  res.replaceChildren();
  const gb = st.mb ? `${(st.mb / 1024).toFixed(1)} GB` : "";
  if (running) {
    $("#mt-run .hw-bar span").style.width = `${st.progress || 0}%`;
    $("#mt-line").textContent = `${Math.round(st.progress || 0)}% · გავლა ${st.current_pass || 1}/${st.passes} · ${mtTestName(st.test)} · ${gb} (~${st.coverage_pct ?? "?"}%) · შეცდომა: ${st.errors || 0}`;
    badge.hidden = false; badge.className = "hw-badge"; badge.textContent = "მიმდინარეობს";
  } else if (st.status) {
    const map = { passed: ["s-ok", "გაიარა"], failed: ["s-bad", "შეცდომებია"], stopped: ["s-warn", "შეჩერდა"], error: ["s-warn", "ვერ დაიწყო"] };
    const [cls, word] = map[st.status] || ["", st.status];
    badge.hidden = false; badge.className = `hw-badge ${cls}`; badge.textContent = word;
    const when = st.finished ? new Date(st.finished).toLocaleString("ka-GE", { dateStyle: "short", timeStyle: "short" }) : "";
    const lines = [];
    if (st.status === "passed") lines.push(`✅ ${gb} შემოწმდა ${st.passes} გავლით — შეცდომა არ არის`);
    if (st.status === "failed") lines.push(`🔴 ${st.errors} შეცდომა ${gb}-ში — RAM სავარაუდოდ დაზიანებულია`);
    if (st.status === "stopped") lines.push(`⏹ შეჩერდა ${Math.round(st.progress || 0)}%-ზე${st.error ? ` (${st.error})` : ""}${st.errors ? `, შეცდომა: ${st.errors}` : ""}`);
    if (st.status === "error") lines.push(`⚠️ ${st.error || ""}`);
    if (st.elapsed_s != null) lines.push(`${when} · ${Math.floor(st.elapsed_s / 60)} წთ ${st.elapsed_s % 60} წმ${st.locked ? " · მეხსიერება ჩაკეტილი იყო RAM-ში" : ""}`);
    for (const e of (st.first_errors || []).slice(0, 4)) lines.push(`• ${mtTestName(e.test)}: ${e.offset_mb} MB — ველოდი ${e.expected}, წავიკითხე ${e.got}`);
    if (st.coverage_pct != null && st.coverage_pct < 60 && st.status !== "error") {
      lines.push(`ℹ️ შემოწმდა RAM-ის ~${st.coverage_pct}% (დანარჩენი Windows-სა და პროგრამებს უჭირავთ). მეტისთვის დახურე პროგრამები, ან 100% — გადატვირთვით.`);
    }
    for (const l of lines) res.appendChild(Object.assign(el("div", "mt-res-line"), { textContent: l }));
  } else {
    badge.hidden = true;
  }
  clearTimeout(mtTimer);
  if (running && state.view === "hw") mtTimer = setTimeout(loadMemtest, 1000);
}

async function loadMemtest() {
  try { renderMemtest(await apiJson("/api/memtest")); } catch { /* ignore */ }
}

// ---------------------------------------------------------------- this PC: system info and live load

const si = { data: null, hist: [], timer: null };
const fmtB = (n) => {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
};
const fmtUp = (s) => { const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60); return `${d ? `${d} დღე ` : ""}${h} სთ ${m} წთ`; };

function siSpark(values, max = 100) {
  const v = values.filter((x) => x != null).slice(-120);
  if (v.length < 2) return "";
  const W = 200, H = 40;
  const pts = v.map((x, i) => `${((i / (v.length - 1)) * W).toFixed(1)},${(H - 2 - (Math.min(x, max) / max) * (H - 4)).toFixed(1)}`);
  return `<svg class="si-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true"><path class="fill" d="M0,${H} L${pts.join(" L")} L${W},${H} Z"/><path d="M${pts.join(" L")}"/></svg>`;
}

const siTone = (pct) => (pct == null ? "" : pct >= 90 ? "bad" : pct >= 70 ? "warn" : "good");

function renderSysinfo() {
  const d = si.data;
  if (!d) return;
  const live = d.live || {};
  const o = d.os || {}, c = d.computer || {};
  const box = $("#si-box");
  box.replaceChildren();
  const card = (cls, html) => { const x = el("div", `hw-card si-card ${cls}`, html); box.appendChild(x); return x; };

  const osCard = card("si-os", `<div class="si-title">${icon("monitor")}<b></b></div><div class="si-sub"></div>
    <div class="hw-facts"></div>`);
  osCard.querySelector("b").textContent = o.pretty || o.caption || "Windows";
  osCard.querySelector(".si-sub").textContent = `${c.name || ""}${c.maker ? ` · ${c.maker} ${c.model || ""}` : ""}`;
  osCard.querySelector(".hw-facts").innerHTML = [
    hwFact("მომხმარებელი", c.user), hwFact(c.domain ? "დომენი" : "სამუშაო ჯგუფი", c.domain || c.workgroup),
    hwFact("დაყენდა", o.installed ? o.installed.slice(0, 10) : null), hwFact("ჩართულია", d.uptime_s != null ? fmtUp(d.uptime_s) : null),
  ].join("");

  const cpu = (d.cpu || [])[0] || {};
  const hist = si.hist;
  const cpuCard = card(`si-cpu t-${siTone(live.cpu)}`, `<div class="si-row"><div><div class="si-title">${icon("chip")}<b>CPU</b></div>
      <div class="si-sub"></div></div><div class="si-big"><b>${live.cpu ?? "—"}%</b><small>${live.mhz ? `${(live.mhz / 1000).toFixed(2)} GHz` : ""}</small></div></div>
    ${siSpark(hist.map((h) => h[1]))}<div class="si-cores"></div>`);
  cpuCard.querySelector(".si-sub").textContent = `${cpu.name || ""} · ${cpu.cores ?? "?"} ბირთვი / ${cpu.threads ?? "?"} ნაკადი`;
  const cores = cpuCard.querySelector(".si-cores");
  (live.cores || []).forEach((v, i) => {
    const b = el("div", `si-core t-${siTone(v)}`, `<span style="height:${Math.max(3, v)}%"></span><small>${i}</small>`);
    b.title = `ნაკადი ${i}: ${v}%`;
    cores.appendChild(b);
  });

  for (const g of d.gpu || []) {
    const vramUsed = (live.vram_dedicated || 0) + (live.vram_shared || 0);
    const gCard = card(`si-gpu t-${siTone(live.gpu)}`, `<div class="si-row"><div><div class="si-title">${icon("image")}<b>GPU</b></div>
        <div class="si-sub"></div></div><div class="si-big"><b>${live.gpu ?? "—"}%</b><small>დატვირთვა</small></div></div>
      ${siSpark(hist.map((h) => h[3]))}<div class="hw-facts"></div>`);
    gCard.querySelector(".si-sub").textContent = g.name;
    gCard.querySelector(".hw-facts").innerHTML = [hwFact("დრაივერი", g.driver), hwFact("VRAM", fmtB(g.vram)),
      hwFact("ვიდეომეხსიერება ახლა", live.vram_dedicated != null ? `${fmtB(vramUsed)}${live.vram_dedicated ? "" : " (საერთო)"}` : null)].join("");
  }

  const ramCard = card(`si-ram t-${siTone(live.ram_pct)}`, `<div class="si-row"><div><div class="si-title">${icon("server")}<b>RAM</b></div>
      <div class="si-sub"></div></div><div class="si-big"><b>${live.ram_pct ?? "—"}%</b><small>გამოყენებული</small></div></div>
    ${siSpark(hist.map((h) => h[2]))}`);
  ramCard.querySelector(".si-sub").textContent = `${fmtB(live.ram_used)} / ${fmtB(live.ram_total)} · თავისუფალი ${fmtB((live.ram_total || 0) - (live.ram_used || 0))}`;

  const parts = d.partitions || [];
  if (parts.length) {
    const pCard = card("si-parts", `<div class="si-title">${icon("hdd")}<b>დანაყოფები</b></div><div class="hw-vols"></div>`);
    for (const p of parts) {
      const row = el("div", `hw-vol${p.pct >= 90 ? " full" : ""}`, `<div class="hw-vol-top"><b></b><span></span></div><div class="hw-bar"><span style="width:${p.pct}%"></span></div>`);
      row.querySelector("b").textContent = `${p.mount} (${p.fs})`;
      row.querySelector(".hw-vol-top span").textContent = `${fmtB(p.used)} / ${fmtB(p.total)} · თავისუფალი ${fmtB(p.free)} · ${p.pct}%`;
      pCard.querySelector(".hw-vols").appendChild(row);
    }
  }

  const ads = (d.adapters || []).filter((a) => !a.virtual || a.status === "Up")
    .sort((a, b) => (a.virtual - b.virtual) || ((b.status === "Up") - (a.status === "Up")));
  if (ads.length) {
    const aCard = card("si-net", `<div class="si-title">${icon("network")}<b>ქსელის ადაპტერები</b></div><div class="si-ads"></div>`);
    for (const a of ads) {
      const row = el("div", `si-ad${a.status === "Up" ? " up" : ""}`, `<div class="si-ad-top"><b></b><span></span></div><div class="si-ad-sub"></div>`);
      row.querySelector("b").textContent = a.name;
      row.querySelector(".si-ad-top span").textContent = a.status === "Up" ? (a.link || "Up") : a.status;
      row.querySelector(".si-ad-sub").textContent = [a.ipv4?.join(", ") || "IP —", `MAC ${a.mac || "—"}`,
        a.gateway ? `gateway ${a.gateway}` : "", a.dns?.length ? `DNS ${a.dns.join(", ")}` : "", a.dhcp === "Enabled" ? "DHCP" : a.ipv4?.length ? "სტატიკური" : "",
        a.description].filter(Boolean).join(" · ");
      aCard.querySelector(".si-ads").appendChild(row);
    }
  }
}

async function loadSysinfo(refresh = false) {
  clearTimeout(si.timer);
  try {
    if (!si.data || refresh) {
      si.data = await apiJson(`/api/sysinfo${refresh ? "?refresh=1" : ""}`);
      si.hist = si.data.history || [];
    } else {
      const r = await apiJson("/api/sysinfo?live=1");
      si.data.live = r.live;
      const last = r.history?.[0];
      if (last && (!si.hist.length || si.hist.at(-1)[0] !== last[0])) si.hist = [...si.hist.slice(-299), last];
    }
    renderSysinfo();
  } catch (err) {
    if (err.message !== "unauthorized" && !si.data) $("#si-box").replaceChildren(Object.assign(el("div", "empty-note"), { textContent: `⚠️ ${err.message}` }));
  }
  if (state.view === "hw" && !document.hidden) si.timer = setTimeout(() => loadSysinfo(), 2000);
}

// ---------------------------------------------------------------- console cable (COM ports)

async function consoleAction(action, port, btn) {
  const out = $("#con-out");
  if (btn) btn.disabled = true;
  out.hidden = false;
  out.textContent = action === "add" ? "ვკითხულობ მოწყობილობას (show version)..." : "ვამოწმებ...";
  try {
    const r = await apiJson("/api/console", { method: "POST", json: { action, port } });
    out.innerHTML = md(r.text || "");
    const bar = el("div", "con-btns");
    for (const b of r.buttons || []) {
      const m = b.command.match(/^\/console (probe|add|login|skipsetup) (\S+)$/);
      const x = el("button", "chip");
      x.type = "button";
      x.textContent = b.label;
      x.addEventListener("click", () => (m ? consoleAction(m[1], m[2], x) : (switchView("chat"), send(b.command))));
      bar.appendChild(x);
    }
    out.appendChild(bar);
    if (action === "add") { loadConsole(); loadOverview(); }
  } catch (err) {
    out.textContent = `⚠️ ${err.message}`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

// every few seconds while the app is open: a newly plugged console cable shows up at once
const conWatch = { known: null, timer: null, seen: {} };

async function watchConsole() {
  clearTimeout(conWatch.timer);
  if (!document.hidden && !$("#app").hidden) {
    try {
      const data = await apiJson("/api/console");
      const now = Object.fromEntries(data.ports.map((p) => [p.port, p]));
      if (conWatch.known) {
        for (const [port, p] of Object.entries(now)) {
          const before = conWatch.known[port];
          if (!before) toast(`🔌 Console კაბელი შეერთდა: ${port}`);
          else if (p.device && !before.device) toast(`✅ ${p.device} დაემატა (${port})`);
          else if (p.state && p.state !== before.state && !p.device && conWatch.seen[port] !== p.state) {
            conWatch.seen[port] = p.state;
            toast(`🔌 ${port}: ${p.state_text || p.state}`);
          }
        }
        for (const port of Object.keys(conWatch.known)) if (!now[port]) toast(`🔌 Console კაბელი გამოერთდა: ${port}`);
        const changed = JSON.stringify(conWatch.known) !== JSON.stringify(now);
        if (changed && state.view === "dash") renderConsole(data);
        if (changed && Object.values(now).some((p) => p.device && !conWatch.known[p.port]?.device)) loadOverview();
      }
      conWatch.known = now;
    } catch { /* offline or logged out */ }
  }
  conWatch.timer = setTimeout(watchConsole, 4000);
}

async function loadConsole() {
  let data;
  try { data = await apiJson("/api/console"); } catch { return; }
  renderConsole(data);
}

function renderConsole(data) {
  const list = $("#con-list");
  list.replaceChildren();
  if (!data.ports.length) {
    list.appendChild(Object.assign(el("div", "empty-note"), { textContent: "COM პორტი არ ჩანს — console კაბელი (USB) შეაერთე." }));
    return;
  }
  for (const r of data.ports) {
    const row = el("div", `con-row${r.device ? " on" : ""}`, `<div class="con-top"><b></b><span></span></div><div class="con-sub"></div><div class="con-btns"></div>`);
    row.querySelector("b").textContent = r.port;
    row.querySelector(".con-top span").textContent = r.device ? `NetAgent-ში: ${r.device}` : r.description;
    row.querySelector(".con-sub").textContent = r.device ? r.description : (r.state_text || r.result || "");
    const btns = row.querySelector(".con-btns");
    const add = (label, action, primary) => {
      const b = el("button", primary ? "btn primary" : "btn");
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", () => consoleAction(action, r.port, b));
      btns.appendChild(b);
    };
    if (!r.device) {
      if (r.state === "setup_dialog" || r.state === "autoinstall") add("setup-ის გამოტოვება", "skipsetup", true);
      else if (r.state === "login_user" || r.state === "login_password") add("შესვლა", "login", true);
      else add("დამატება", "add", true);
      add("შემოწმება", "probe");
    }
    list.appendChild(row);
  }
}

// ---------------------------------------------------------------- temperatures

let tpTimer = null;
const TP_NAMES = { cpu: "CPU", gpu: "GPU", disk: "დისკი" };

function renderTemps(r) {
  const card = $("#tp-card");
  const head = r.summary || {};
  const lv = r.levels || {};
  const th = r.thresholds || {};
  const hist = r.history || [];
  const tiles = ["cpu", "gpu", "disk"].map((k, i) => {
    const v = head[k];
    const col = i + 1;
    return `<div class="tp-tile l-${lv[k] || "none"}"><span>${TP_NAMES[k]}</span><b>${v == null ? "—" : `${Math.round(v)}°C`}</b>
      ${siSpark(hist.map((h) => h[col]), Math.max(100, ...(th[k] || [0, 100])))}<small>${th[k] ? `${th[k][0]}° / ${th[k][1]}°` : ""}</small></div>`;
  }).join("");
  const cores = (r.sensors || []).filter((s) => s.kind === "cpu" && /core/i.test(s.name) && !/max|average/i.test(s.name));
  card.innerHTML = `<div class="tp-tiles">${tiles}</div>
    ${cores.length ? `<div class="tp-cores">${cores.slice(0, 16).map((s) => `<span class="l-${s.value >= (th.cpu || [75, 90])[1] ? "red" : s.value >= (th.cpu || [75, 90])[0] ? "yellow" : "green"}">${esc(s.name.replace(/CPU /, ""))} ${Math.round(s.value)}°</span>`).join("")}</div>` : ""}
    <div class="tp-src"></div><div class="tp-msg"></div>
    <details class="tp-th"><summary>ზღვრები (ყვითელი / წითელი, °C)</summary><div class="tp-th-rows"></div>
      <button type="button" class="btn" id="tp-save">შენახვა</button></details>`;
  card.querySelector(".tp-src").textContent = r.sources?.length ? `წყარო: ${r.sources.join(", ")}` : "";
  card.querySelector(".tp-msg").textContent = r.message || "";
  const rows = card.querySelector(".tp-th-rows");
  for (const k of ["cpu", "gpu", "disk"]) {
    const row = el("label", "tp-th-row", `<span>${TP_NAMES[k]}</span><input type="number" min="20" max="120" data-k="${k}" data-i="0"><input type="number" min="20" max="120" data-k="${k}" data-i="1">`);
    row.querySelectorAll("input").forEach((inp) => { inp.value = (th[k] || [])[Number(inp.dataset.i)] ?? ""; });
    rows.appendChild(row);
  }
  card.querySelector("#tp-save").addEventListener("click", async () => {
    const body = {};
    card.querySelectorAll(".tp-th-rows input").forEach((inp) => { (body[inp.dataset.k] ||= [0, 0])[Number(inp.dataset.i)] = Number(inp.value); });
    try { await apiJson("/api/temps/thresholds", { method: "POST", json: body }); toast("შენახულია"); loadTemps(); } catch (e) { toast(e.message); }
  });
}

async function loadTemps() {
  clearTimeout(tpTimer);
  const open = $("#tp-card").querySelector("details[open]");  // do not close the editor while typing
  if (!open) {
    try { renderTemps(await apiJson("/api/temps")); } catch (err) {
      if (err.message !== "unauthorized") $("#tp-card").textContent = `⚠️ ${err.message}`;
    }
  }
  if (state.view === "hw" && !document.hidden) tpTimer = setTimeout(loadTemps, 5000);
}

// ---------------------------------------------------------------- disk surface scan

let ssTimer = null;
const SS_WORD = { ok: ["s-ok", "ცუდი სექტორი არ არის"], warn: ["s-warn", "ნელი ადგილებია"], bad: ["s-bad", "ცუდი სექტორებია"],
  stopped: ["s-warn", "შეჩერდა"], aborted: ["s-bad", "შეწყდა"], declined: ["s-warn", "UAC უარყოფილია"],
  waiting_uac: ["", "ელოდება UAC-ს"], running: ["", "მიმდინარეობს"] };

function renderSurf(r) {
  const st = r.status || {};
  const s = st.status;
  const running = s === "running" || s === "waiting_uac";
  $("#ss-start").disabled = running;
  $("#ss-stop").hidden = s !== "running";
  $("#ss-run").hidden = s !== "running";
  const badge = $("#ss-badge");
  badge.hidden = !s;
  if (s) { const [cls, word] = SS_WORD[s] || ["", s]; badge.className = `hw-badge ${cls}`; badge.textContent = word; }
  const fmtEta = (x) => (x >= 3600 ? `${Math.floor(x / 3600)} სთ ${Math.floor((x % 3600) / 60)} წთ` : `${Math.floor(x / 60)} წთ ${x % 60} წმ`);
  if (s === "running") {
    $("#ss-run .hw-bar span").style.width = `${st.progress || 0}%`;
    $("#ss-line").textContent = `${(st.progress || 0).toFixed(1)}% · ${st.speed_mbps || 0} MB/s · დარჩა ~${fmtEta(st.eta_s || 0)} · ცუდი: ${st.bad_count || 0} · ნელი: ${(st.slow || 0) + (st.very_slow || 0)}`;
  }
  const map = $("#ss-map");
  map.replaceChildren();
  if (st.segments) {
    for (const ch of st.segments) map.appendChild(el("span", `ss-c c${ch}`));
    $("#ss-legend").hidden = false;
  }
  const res = $("#ss-result");
  res.replaceChildren();
  const line = (txt) => res.appendChild(Object.assign(el("div", "mt-res-line"), { textContent: txt }));
  if (s === "waiting_uac") line("🖥 კომპიუტერზე Windows ითხოვს ადმინის დადასტურებას — დააჭირე „Yes“.");
  if (s === "declined") line("UAC არ დადასტურდა — სკანი არ დაწყებულა.");
  if (["ok", "warn", "bad", "stopped", "aborted"].includes(s)) {
    line(`${st.label || ""} · წაკითხულია ${(st.progress || 0).toFixed(1)}% · ${st.speed_mbps || 0} MB/s · ${fmtEta(st.elapsed_s || 0)}`);
    if (st.bad_count) line(`🔴 ცუდი სექტორები: ${st.bad_count} (LBA ${(st.bad_sectors || []).slice(0, 8).join(", ")}${st.bad_count > 8 ? "…" : ""}) — ახლავე გააკეთე მნიშვნელოვანი ფაილების backup.`);
    else if (st.very_slow) line(`🟠 ძალიან ნელი ბლოკები: ${st.very_slow} — ხშირად სუსტი სექტორის პირველი ნიშანია.`);
    else if (s === "ok") line("✅ ყველა სექტორი იკითხება, ნელი ადგილი არ არის.");
    if (st.error) line(`⚠️ ${st.error}`);
  }
  const hist = Object.values(r.history || {}).flat().sort((a, b) => (a.finished < b.finished ? 1 : -1)).slice(0, 4);
  if (hist.length > 1 || (hist.length && !["ok", "warn", "bad"].includes(s))) {
    line("ისტორია:");
    for (const h of hist) line(`• ${h.finished?.replace("T", " ").slice(0, 16)} · ${h.label || ""} · ${(SS_WORD[h.status] || ["", h.status])[1]}${h.bad_count ? ` (${h.bad_count})` : ""}`);
  }
  clearTimeout(ssTimer);
  if (running && state.view === "hw") ssTimer = setTimeout(loadSurf, 1500);
}

async function loadSurf() {
  try { renderSurf(await apiJson("/api/surfscan")); } catch { /* ignore */ }
}

// ---------------------------------------------------------------- who uses the internet

const bw = { period: "15", timer: null };
const bwHuman = (n) => (n >= 1e12 ? `${(n / 1e12).toFixed(1)} TB` : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${Math.round(n)} B`);
const bwRate = (b) => (b >= 1e5 ? `${(b / 1e6).toFixed(1)} Mbps` : `${Math.round(b / 1e3)} kbps`);

function renderBandwidth(r) {
  const list = $("#bw-list");
  list.replaceChildren();
  const rows = r.rows || [];
  const max = Math.max(1, ...rows.map((x) => x.down + x.up + (x.down_bps + x.up_bps) / 8));
  for (const x of rows.slice(0, 12)) {
    const val = x.down + x.up + (x.down_bps + x.up_bps) / 8;
    const row = el("div", "bw-row", `<span class="lv-kind">${icon(x.icon || "help")}</span><div class="bw-main">
        <div class="bw-top"><b></b><span></span></div><div class="bw-bar"><span class="d"></span><span class="u"></span></div><div class="bw-sub"></div></div>`);
    row.querySelector("b").textContent = x.name;
    row.querySelector(".bw-top span").textContent = bwHuman(x.down + x.up);
    const share = (100 * val) / max;
    const dShare = x.down + x.up ? (x.down / (x.down + x.up)) * share : share;
    row.querySelector(".bw-bar .d").style.width = `${dShare}%`;
    row.querySelector(".bw-bar .u").style.width = `${Math.max(0, share - dShare)}%`;
    row.querySelector(".bw-sub").textContent = [`ჩამოტვირთვა (download) ${bwHuman(x.down)}`, `ატვირთვა (upload) ${bwHuman(x.up)}`,
      x.down_bps > 1e4 ? `ახლა ${bwRate(x.down_bps)}` : "", x.ip && x.ip !== x.name ? x.ip : "", x.port ? `პორტი ${x.port}` : ""].filter(Boolean).join(" · ");
    list.appendChild(row);
  }
  if (!rows.length && !r.hint) list.appendChild(Object.assign(el("div", "empty-note"), { textContent: "ამ პერიოდში ტრაფიკი არ ჩანს." }));
  $("#bw-apps").textContent = (r.apps || []).length ? `რა: ${r.apps.map((a) => `${a.app} ${bwHuman(a.bytes)}`).join(" · ")}` : "";
  const hint = $("#bw-hint");
  hint.replaceChildren();
  if (r.hint) {
    const [first, ...rest] = r.hint.split("\n");
    hint.appendChild(Object.assign(el("p"), { textContent: first }));
    if (rest.length) hint.appendChild(Object.assign(el("pre"), { textContent: rest.join("\n") }));
  }
}

async function loadBandwidth() {
  clearTimeout(bw.timer);
  try { renderBandwidth(await apiJson(`/api/bandwidth?period=${bw.period}`)); } catch { /* ignore */ }
  if (state.view === "dash" && !document.hidden) bw.timer = setTimeout(loadBandwidth, 30000);
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
  // `ready` never settles when the service worker could not be registered (some embedded browsers, private
  // modes): without a time limit the status stayed at "…" and the switch kept waiting forever.
  const reg = await Promise.race([navigator.serviceWorker.ready, new Promise((r) => setTimeout(() => r(null), 4000))]);
  if (!reg) return { supported: false, reason: "sw" };
  return { supported: true, reg, sub: await reg.pushManager.getSubscription() };
}

async function refreshPushUI() {
  const st = await pushState().catch(() => ({ supported: false }));
  const toggle = $("#push-toggle");
  if (!st.supported) {
    $("#push-status").textContent = st.reason === "sw"
      ? "მიუწვდომელია: ამ ბრაუზერმა service worker ვერ ჩატვირთა (სცადე Chrome ან დაინსტალირებული აპი)"
      : "მიუწვდომელია ამ ბრაუზერში (საჭიროა HTTPS, მაგ. Tailscale)";
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

// ---------------------------------------------------------------- live network map (Network tab)
const SVGNS = "http://www.w3.org/2000/svg";
const svgEl = (tag, attrs = {}) => {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
};
let mapData = null;

async function loadMap(refresh = false) {
  const box = $("#map-box");
  if (refresh) box.classList.add("loading");
  try {
    mapData = await apiJson(`/api/topology${refresh ? "?refresh=1" : ""}`);
    renderMap();
    if (refresh) toast("კაბელები განახლდა");
  } catch (err) {
    if (err.message !== "unauthorized") box.replaceChildren(Object.assign(el("div", "empty-note"), { textContent: `⚠️ ${err.message}` }));
  } finally {
    box.classList.remove("loading");
  }
}

function renderMap() {
  const box = $("#map-box");
  const d = mapData;
  $("#map-pop").hidden = true;
  if (!d || !d.nodes.length) {
    box.replaceChildren(Object.assign(el("div", "empty-note"), {
      textContent: "რუკისთვის საჭიროა მართვადი როუტერები/switch-ები devices.yaml-ში (კაბელებს CDP/LLDP-ით ვპოულობ).",
    }));
    return;
  }
  const W = 480, H = Math.max(220, (d.rows || 3) * 105);  // phone-sized canvas, one row per hop
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "map-svg", role: "img", "aria-label": "ქსელის რუკა" });
  const pos = Object.fromEntries(d.nodes.map((n) => [n.id, [n.x * W, n.y * H]]));
  for (const l of d.links) {
    const a = pos[l.a], b = pos[l.b];
    if (!a || !b) continue;
    const u = l.util;
    const cls = u == null ? "l-none" : u >= 80 ? "l-bad" : u >= 50 ? "l-warn" : "l-ok";
    const line = svgEl("line", { x1: a[0], y1: a[1], x2: b[0], y2: b[1], class: `map-link ${cls}`,
      "stroke-width": (2 + Math.min(u || 0, 100) / 16).toFixed(1) });
    const t = svgEl("title");
    t.textContent = `${l.a} ${l.a_port} ↔ ${l.b} ${l.b_port}` + (u == null ? "" : ` · დატვირთვა ${u}%`);
    line.appendChild(t);
    svg.appendChild(line);
    if (u != null) {
      const lbl = svgEl("text", { x: (a[0] + b[0]) / 2 + 8, y: (a[1] + b[1]) / 2, class: "map-util" });
      lbl.textContent = `${Math.round(u)}%`;
      svg.appendChild(lbl);
    }
  }
  for (const n of d.nodes) {
    const [x, y] = pos[n.id];
    const g = svgEl("g", { class: `map-node ${n.up === true ? "up" : n.up === false ? "down" : "ext"}`, tabindex: "0", role: "button" });
    g.appendChild(svgEl("circle", { cx: x, cy: y, r: 19 }));
    const ini = svgEl("text", { x, y: y + 4.5, class: "map-ini" });
    ini.textContent = n.id.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
    const name = svgEl("text", { x, y: y + 34, class: "map-name" });
    name.textContent = n.id.length > 13 ? `${n.id.slice(0, 12)}…` : n.id;
    g.append(ini, name);
    const open = (ev) => { ev.stopPropagation(); mapPopup(n, x / W, y / H); };
    g.addEventListener("click", open);
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") open(e); });
    svg.appendChild(g);
  }
  svg.addEventListener("click", () => { $("#map-pop").hidden = true; });
  const note = el("div", "map-note");
  note.textContent = `${d.up} ონლაინ · ${d.down} გათიშული · კაბელები: ${d.links.length}` + (d.generated ? ` · აღმოჩენილია ${d.generated.replace("T", " ")}` : "");
  box.replaceChildren(svg, note);
}

function mapPopup(n, fx, fy) {
  const pop = $("#map-pop");
  pop.replaceChildren();
  const title = el("div", "map-pop-title");
  title.textContent = n.id;
  const sub = el("div", "map-pop-sub");
  sub.textContent = [n.ip, n.type, n.up === true ? `ონლაინ${n.latency_ms != null ? ` · ${Math.round(n.latency_ms)} ms` : ""}` : n.up === false ? "გათიშულია" : "გარე მეზობელი (inventory-ში არ არის)"]
    .filter(Boolean).join(" · ");
  pop.append(title, sub);
  const acts = el("div", "map-pop-acts");
  const add = (label, fn) => { const b = el("button", "chip"); b.type = "button"; b.textContent = label; b.addEventListener("click", fn); acts.appendChild(b); };
  if (n.known) {
    add("ჯანმრთელობა", () => send(`/health ${n.id}`));
    add("დიაგნოსტიკა", () => send(`/diagnose ${n.id}`));
    add("ინტერფეისები", () => { switchView("chat"); send(`/cmd ${n.id} show ip interface brief`); });
  } else if (n.ip) {
    add("შემოწმება", () => send(`/diagnose ${n.ip}`));
  }
  pop.appendChild(acts);
  pop.style.left = `${Math.min(Math.max(fx * 100, 4), 60)}%`;
  pop.style.top = `${Math.min(fy * 100 + 6, 70)}%`;
  pop.hidden = false;
}

// ---------------------------------------------------------------- Live Devices
// Polls /api/live while the tab is open (the server pings in the background, so nothing here blocks).
const live = { prev: {}, fresh: true, data: null, sort: "ip", dir: 1, search: "", selected: null, timer: null, detailAt: 0, filter: "all", days: 1 };

const ipNum = (ip) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const LIVE_SORT = {
  status: (r) => (r.online ? 0 : 1), ip: (r) => ipNum(r.ip), mac: (r) => (r.mac === "N/A" ? "~" : r.mac),
  vendor: (r) => (r.vendor || "~").toLowerCase(), hostname: (r) => (r.label || r.hostname || r.kind_label || "~").toLowerCase(),
  ms: (r) => (r.latency_ms == null ? 1e9 : r.latency_ms), first: (r) => r.first_seen, last: (r) => r.last_seen,
};

function liveTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const today = d.toDateString() === new Date().toDateString();
  return d.toLocaleString("ka-GE", today ? { hour: "2-digit", minute: "2-digit", second: "2-digit" }
    : { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function liveMs(ms) {
  return ms < 1 ? "<1 ms" : ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

function liveCell(tr, cls, text, sub) {
  const td = el("td", cls || "");
  const main = el("span", "lv-main");
  main.textContent = text;
  td.appendChild(main);
  if (sub) { const s = el("span", "lv-sub"); s.textContent = sub; td.appendChild(s); }
  tr.appendChild(td);
  return td;
}

function renderLive() {
  const d = live.data;
  if (!d) return;
  // interface + interval pickers
  const sel = $("#live-iface");
  const want = d.settings.interface || "";
  const opts = [["", `ავტომატური${d.interface && !want ? ` — ${d.interface.name} ${d.interface.network}` : ""}`],
    ...d.interfaces.map((i) => [i.name, `${i.name} — ${i.network}${i.virtual ? " (ვირტუალური)" : ""}`])];
  if (sel.dataset.sig !== JSON.stringify(opts) + want) {
    sel.replaceChildren(...opts.map(([v, t]) => { const o = el("option"); o.value = v; o.textContent = t; return o; }));
    sel.value = want;
    sel.dataset.sig = JSON.stringify(opts) + want;
  }
  const iv = $("#live-interval");
  if (document.activeElement !== iv) iv.value = String(d.settings.ping_interval);
  if (![...iv.options].some((o) => o.value === iv.value)) iv.value = "3";

  const net = d.interface ? `${d.interface.network} · ${d.interface.name}` : "ინტერფეისი არ არის";
  const ago = d.last_scan ? Math.max(0, Math.round(d.now - d.last_scan)) : null;
  $("#live-summary").innerHTML = `<span class="lv-on">● ${d.online} ონლაინ</span><span class="lv-off">● ${d.offline} ოფლაინ</span>`
    + `<span>${esc(net)}</span><span>${d.scanning ? "სკანირება..." : ago == null ? "პირველი სკანი..." : `სკანი ${ago} წმ წინ`}</span>`;
  $("#live-summary").title = d.method;
  $("#live-notices").replaceChildren(...d.notices.map((n) => { const p = el("p", "live-notice"); p.textContent = `⚠️ ${n}`; return p; }));

  // rows: search, sort, render as text only (names come from the network: never innerHTML)
  const q = live.search.trim().toLowerCase();
  const rows = d.devices.filter((r) => (live.filter === "all" || !r.trusted)
    && (!q || [r.ip, r.mac, r.vendor, r.hostname, r.label, r.kind_label].join(" ").toLowerCase().includes(q)));
  const unknown = d.devices.filter((r) => !r.trusted).length;
  $('#live-filter [data-filter="unknown"]').textContent = unknown ? `უცნობი (${unknown})` : "უცნობი";
  // settings panel mirrors the server (unless the user is editing it right now)
  if (!$("#live-settings").contains(document.activeElement)) {
    $("#live-alert-unknown").checked = d.settings.alert_unknown;
    $("#live-night").checked = d.settings.night_alerts;
    $("#live-night-window").value = d.settings.night;
  }
  const key = LIVE_SORT[live.sort] || LIVE_SORT.ip;
  rows.sort((a, b) => { const x = key(a), y = key(b); return (x > y ? 1 : x < y ? -1 : ipNum(a.ip) - ipNum(b.ip)) * live.dir; });
  document.querySelectorAll(".live-table th button").forEach((b) => {
    b.dataset.dir = b.dataset.sort === live.sort ? (live.dir > 0 ? "asc" : "desc") : "";
  });
  const body = $("#live-rows");
  body.replaceChildren();
  if (!rows.length) {
    const tr = el("tr", "lv-empty");
    const td = el("td");
    td.colSpan = 8;
    td.textContent = d.devices.length ? "ვერაფერი მოიძებნა" : d.scanning || !d.last_scan ? "ვეძებ მოწყობილობებს..." : "მოწყობილობა ვერ ვიპოვე";
    tr.appendChild(td);
    body.appendChild(tr);
  }
  for (const r of rows) {
    const was = live.prev[r.key];
    const flash = was === undefined || was === r.online ? "" : r.online ? " flash-on" : " flash-off";
    live.prev[r.key] = r.online;
    const tr = el("tr", `${r.online ? "is-on" : "is-off"}${r.new ? " is-new" : ""}${live.selected === r.key ? " is-sel" : ""}${flash}`);
    tr.tabIndex = 0;
    const st = el("td", "c-st", `<span class="lv-dot"></span><span class="sr-only"></span>`);
    st.lastChild.textContent = r.online ? "Online" : "Offline";
    st.title = r.online ? "Online" : `Offline · ${r.misses} პასუხი გამოტოვა`;
    tr.appendChild(st);
    liveCell(tr, "c-ip", r.ip, r.mac);
    liveCell(tr, "c-mac", r.mac);
    liveCell(tr, "c-vendor", r.vendor || "—");
    const name = liveCell(tr, "c-name", r.label || r.hostname || (r.kind ? r.kind_label : "—"), r.vendor || "");
    name.insertBefore(el("span", "lv-kind", icon(r.icon)), name.firstChild);
    name.firstChild.title = r.kind_label;
    if (r.label && r.hostname) name.title = `${r.hostname} (${r.hostname_source})`;
    else if (r.hostname) name.title = r.hostname_source;
    for (const [flag, text, cls] of [[!r.trusted, "უცნობი", "tag-unknown"], [r.new, "NEW", "tag-new"], [r.self, "ეს PC", "tag"], [r.gateway, "როუტერი", "tag"]]) {
      if (flag) { const t = el("span", `lv-tag ${cls}`); t.textContent = text; name.querySelector(".lv-main").after(t); }
    }
    const ms = r.latency_ms;
    const tone = ms == null ? "" : ms < 20 ? "good" : ms < 100 ? "warn" : "bad";
    // no ping answer this round: a device that normally answers just lost one; one that never does blocks ICMP
    const quiet = r.icmp ? "დაიკარგა" : "ARP ✓";
    const msCell = liveCell(tr, `c-ms ${ms == null && r.online && r.icmp ? "warn" : tone}`, !r.online ? "—" : ms != null ? liveMs(ms) : quiet);
    if (r.online && ms == null) {
      msCell.title = r.icmp ? "ეს ping დაიკარგა, მაგრამ ARP-ზე პასუხობს — ქსელშია"
        : "ping-ს არ პასუხობს (firewall), მაგრამ ARP-ზე პასუხობს — ქსელშია";
    }
    liveCell(tr, "c-seen", liveTime(r.first_seen));
    liveCell(tr, "c-seen", r.online ? "ახლა" : liveTime(r.last_seen));
    const open = () => { live.selected = live.selected === r.key ? null : r.key; live.detailAt = 0; renderLive(); };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    body.appendChild(tr);
  }

  // events
  const evBox = $("#live-events");
  evBox.replaceChildren();
  if (!d.events.length) evBox.appendChild(el("div", "empty-note", "შემოსვლა/გასვლა ჯერ არ დაფიქსირებულა."));
  const EV = { new: ["sparkle", "blue", "ახალი მოწყობილობა შემოვიდა"], online: ["check", "green", "დაბრუნდა ქსელში"],
    offline: ["alert", "red", "გავიდა ქსელიდან"] };
  for (const e of d.events.slice(0, 20)) {
    const [ico, color, what] = EV[e.event] || ["bell", "gray", e.event];
    const item = el("div", "event", `<span class="ev-ico ${color}">${icon(ico)}</span><div><div class="ev-when"></div><div class="lv-ev"></div></div>`);
    item.querySelector(".ev-when").textContent = liveTime(e.ts);
    item.querySelector(".lv-ev").textContent = `${what}: ${e.hostname || e.vendor || e.ip} · ${e.ip} · ${e.mac}`;
    evBox.appendChild(item);
  }
  renderLiveDetail();
}

function liveGraph(points) {
  const W = 600, H = 120, n = points.length;
  if (!n) return "";
  const vals = points.map((p) => p[1]).filter((v) => v != null);
  const max = Math.max(...vals, 5) * 1.15;
  const x = (i) => (n === 1 ? W : (i / (n - 1)) * W);
  const y = (v) => H - 4 - (v / max) * (H - 10);
  let path = "", pen = false, miss = "";
  points.forEach((p, i) => {
    if (p[1] == null) { pen = false; miss += `<rect x="${(x(i) - 1).toFixed(1)}" y="${H - 6}" width="3" height="6"/>`; return; }
    path += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`;
    pen = true;
  });
  const grid = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${W}" y1="${(H - 4 - f * (H - 10)).toFixed(1)}" y2="${(H - 4 - f * (H - 10)).toFixed(1)}"/>`).join("");
  return `<svg class="lv-graph" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true"><g class="lv-grid">${grid}</g>`
    + `<g class="lv-miss">${miss}</g><path d="${path}"/></svg><div class="lv-axis"><span>0</span><span>${Math.round(max)} ms</span></div>`;
}

async function renderLiveDetail() {
  const box = $("#live-detail");
  const row = live.data?.devices.find((r) => r.key === live.selected);
  if (!row) { box.hidden = true; return; }
  box.hidden = false;
  if (Date.now() - live.detailAt < 1500 && box.dataset.key === row.key) return;
  live.detailAt = Date.now();
  let h = null;
  try { h = await apiJson(`/api/live/device?key=${encodeURIComponent(row.key)}`); } catch { /* removed meanwhile */ }
  if (live.selected !== row.key) return;
  box.dataset.key = row.key;
  box.innerHTML = `<div class="lv-head"><div><div class="lv-title"></div><div class="lv-subtitle"></div></div>
      <button type="button" class="ghost-icon" aria-label="დახურვა">${icon("x")}</button></div>
    <div class="lv-stats"></div><div class="lv-graph-wrap">${h ? liveGraph(h.points) : ""}</div>
    <div class="lv-tl-head"><span>ონლაინ ისტორია</span><div class="segmented lv-days">
      <button type="button" data-days="1">24 სთ</button><button type="button" data-days="7">7 დღე</button></div></div>
    <div class="lv-timeline"></div>
    <dl class="lv-facts"></dl>
    <div class="lv-iot"></div>
    <div class="lv-actions"><button type="button" class="chip" data-act="trust">${icon("check")}<span></span></button>
      <button type="button" class="chip" data-act="ports">${icon("search")}<span>ღია პორტები</span></button>
      <button type="button" class="chip" data-act="name">${icon("note")}<span>სახელის მიცემა</span></button></div>`;
  box.querySelector(".lv-title").textContent = row.label || row.hostname || row.vendor || row.ip;
  box.querySelector(".lv-subtitle").textContent = `${row.online ? "Online" : "Offline"} · ${row.ip}`;
  const stats = h ? [["მინ.", h.min_ms], ["საშ.", h.avg_ms], ["მაქს.", h.max_ms]] : [];
  box.querySelector(".lv-stats").replaceChildren(...stats.map(([k, v]) => {
    const s = el("span"); s.textContent = `${k} ${v == null ? "—" : liveMs(v)}`; return s;
  }), ...(h && h.loss_pct != null ? [Object.assign(el("span"), { textContent: `დანაკარგი ${h.loss_pct}% (${h.samples} გაზომვა)` })] : []));
  const facts = [["ტიპი", row.kind_label], ["სტატუსი", row.trusted ? "ნაცნობი (შენი)" : "უცნობი"], ["MAC", row.mac], ["მწარმოებელი", row.vendor || "—"],
    ["სერვისები", row.ports && row.ports.length ? row.ports.join(", ") : "ღია პორტი არ ჩანს"],
    ["ქსელის სახელი", row.hostname ? `${row.hostname} · ${row.hostname_source}` : "ვერ გაირკვა (DNS, NetBIOS, mDNS)"],
    ["პირველად", liveTime(row.first_seen)], ["ბოლოს", row.online ? "ახლა" : liveTime(row.last_seen)]];
  box.querySelector(".lv-facts").replaceChildren(...facts.flatMap(([k, v]) => {
    const dt = el("dt"); dt.textContent = k; const dd = el("dd"); dd.textContent = v; return [dt, dd];
  }));
  box.querySelector(".ghost-icon").addEventListener("click", () => { live.selected = null; renderLive(); });
  const trustBtn = box.querySelector('[data-act="trust"]');
  trustBtn.lastChild.textContent = row.trusted ? "ნაცნობებიდან მოხსნა" : "ჩემია (ნაცნობი)";
  trustBtn.addEventListener("click", () => apiJson("/api/live/trust", { method: "POST", json: { key: row.key, trusted: !row.trusted } })
    .then(() => { toast(row.trusted ? "მოიხსნა ნაცნობებიდან" : "მოინიშნა ნაცნობად"); live.detailAt = 0; loadLive(); })
    .catch((e) => toast(e.message)));
  box.querySelectorAll(".lv-days button").forEach((b) => {
    b.classList.toggle("on", Number(b.dataset.days) === live.days);
    b.addEventListener("click", () => { live.days = Number(b.dataset.days); live.detailAt = 0; renderLiveDetail(); });
  });
  apiJson(`/api/live/timeline?key=${encodeURIComponent(row.key)}&days=${live.days}`)
    .then((tl) => { if (live.selected === row.key) box.querySelector(".lv-timeline").innerHTML = liveTimeline(tl); })
    .catch(() => {});
  renderIotFindings(box.querySelector(".lv-iot"), row.ip);
  box.querySelector('[data-act="ports"]').addEventListener("click", () => { switchView("chat"); send(`/scan ${row.ip}`); });
  box.querySelector('[data-act="name"]').addEventListener("click", () => {
    switchView("chat");
    const input = $("#input");
    input.value = `/name ${row.mac !== "N/A" ? row.mac : row.ip} `;
    input.focus();
    updateSend();
  });
}

function liveTimeline(tl) {
  const n = tl.values.length, W = 600, H = 26;
  const w = W / n;
  let cells = "";
  tl.values.forEach((v, i) => {
    const cls = v == null ? "tl-na" : v >= 0.99 ? "tl-on" : v > 0 ? "tl-part" : "tl-off";
    cells += `<rect class="${cls}" x="${(i * w).toFixed(2)}" y="0" width="${(w + 0.3).toFixed(2)}" height="${H}"/>`;
  });
  const ticks = [];
  const slots = 4;
  for (let i = 0; i <= slots; i++) {
    const t = new Date((tl.start + (i / slots) * n * tl.slot_seconds) * 1000);
    ticks.push(`<span>${tl.days === 1 ? t.toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }) : t.toLocaleDateString("ka-GE", { day: "2-digit", month: "2-digit" })}</span>`);
  }
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${cells}</svg>`
    + `<div class="lv-ticks">${ticks.join("")}</div><div class="lv-tl-sum">ონლაინ: ${tl.online_hours} სთ ${tl.days === 1 ? "ბოლო 24 სთ-ში" : "ბოლო 7 დღეში"}</div>`;
}

let iotCache = { at: 0, data: null };

async function renderIotFindings(box, ip) {
  if (Date.now() - iotCache.at > 20_000) {
    try { iotCache = { at: Date.now(), data: await apiJson("/api/iot") }; } catch { return; }
  }
  const fs = iotCache.data?.devices?.[ip];
  box.replaceChildren();
  if (!fs) return;
  const head = el("div", "lv-tl-head");
  head.textContent = `IoT შემოწმება · ${liveTime(Date.parse(iotCache.data.ts) / 1000)}`;
  box.appendChild(head);
  for (const f of fs) {
    const item = el("div", `iot-finding ${f.severity}`, "<b></b><span></span>");
    item.firstChild.textContent = f.title;
    item.lastChild.textContent = f.severity === "ok" ? "" : f.advice;
    box.appendChild(item);
  }
}

function runIotCheck() {
  iotCache.at = 0;
  send("/iot");  // full report in the chat; per-device findings appear in Live details afterwards
}

async function loadLive() {
  try {
    live.data = await apiJson("/api/live");
    renderLive();
    if (live.fresh && live.data.devices.length) { live.fresh = false; replay($(".live-table"), "rows-in", 1200); }
  } catch (err) {
    if (err.message !== "unauthorized") {
      $("#live-summary").textContent = `⚠️ ${err.message}`;
    }
  }
}

function startLive() {
  stopLive();
  live.fresh = true;
  const step = async () => {
    if (state.view !== "live") return;
    if (!document.hidden) await loadLive();
    const every = Math.max(2, live.data?.settings.ping_interval || 3) * 1000;
    live.timer = setTimeout(step, every);
  };
  step();
}

function stopLive() {
  clearTimeout(live.timer);
  live.timer = null;
}

async function liveSetting(change) {
  try {
    await apiJson("/api/live/settings", { method: "POST", json: change });
    toast("შენახულია");
    startLive();
  } catch (err) {
    toast(err.message);
    loadLive();
  }
}

// ---------------------------------------------------------------- views & auth

function applyLayout() {
  const two = isTwoPane();
  const app = $("#app");
  app.classList.toggle("two-pane", two);
  app.dataset.view = state.view;
  const sidePane = two && state.view === "chat";
  for (const v of ["chat", "dash", "settings", "term", "live", "hw"]) {
    const node = $(`#view-${v}`);
    const show = v === state.view || (sidePane && v === "dash");
    if (show && node.hidden) replay(node, "view-in", 800);
    node.hidden = !show;
  }
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
  if (name === "dash") { loadMap(); loadRooms(); loadDz(); loadConsole(); loadBandwidth(); }
  if (name !== "dash") dzWalkStop();
  if (name === "settings") {
    refreshPushUI();
    apiJson("/api/command", { method: "POST", json: { line: "/usage" } })
      .then((r) => { $("#usage").innerHTML = md(r.text.split("\n").slice(1).join("\n")); })
      .catch(() => {});
  }
  if (name === "chat") scrollDown();
  if (name === "term") openTerminal();
  if (name === "hw") { loadHw(); loadMemtest(); loadSysinfo(); loadTemps(); loadSurf(); }
  else clearTimeout(si.timer);
  if (name === "live") startLive();
  else stopLive();
}

// ---------------------------------------------------------------- terminal (read-only, via /cmd)

const TERM_CHIPS = {
  mikrotik: ["/ip address print", "/ip route print", "/interface print", "/ip arp print", "/log print", "/system resource print"],
  juniper: ["show interfaces terse", "show route", "show bgp summary", "show log messages | last 30", "show system uptime"],
  default: ["show ip interface brief", "show ip route", "show interfaces description", "show version", "show logging", "show cdp neighbors"],
};
const termHistory = [];
let termPos = 0;

// ---------------------------------------------------------------- terminal: Cisco-style completion
// Tab completes the word (or lists the options), "?" shows what can come next,
// and abbreviations ("sh ip int br") are expanded to full words before sending,
// because the server's read-only guard only accepts full verbs like "show".
const L = Object.freeze({}); // leaf: nothing known after this word
const RO = { print: { detail: L, terse: L, "count-only": L, "without-paging": L }, export: L }; // RouterOS reads
const TERM_TREE = {
  cisco: {
    show: {
      version: L, clock: L, users: L, inventory: L, history: L, license: L, module: L, logging: L, arp: L,
      "running-config": { interface: L }, "startup-config": L, "access-lists": L, "port-security": L, snmp: L,
      ip: {
        interface: { brief: L }, route: { summary: L, connected: L, static: L, ospf: L, bgp: L, eigrp: L },
        arp: L, bgp: { summary: L, neighbors: L }, ospf: { neighbor: L, interface: { brief: L }, database: L },
        eigrp: { neighbors: L, topology: L }, protocols: L, dhcp: { binding: L, pool: L, conflict: L },
        nat: { translations: L, statistics: L }, "access-lists": L, ssh: L,
      },
      ipv6: { interface: { brief: L }, route: L, neighbors: L },
      interfaces: { status: L, description: L, trunk: L, counters: { errors: L }, summary: L, switchport: L },
      vlan: { brief: L }, mac: { "address-table": { dynamic: L, count: L } },
      "spanning-tree": { summary: L, root: L, blockedports: L },
      cdp: { neighbors: { detail: L } }, lldp: { neighbors: { detail: L } },
      ntp: { status: L, associations: L }, processes: { cpu: { sorted: L, history: L }, memory: { sorted: L } },
      memory: { statistics: L }, environment: { all: L }, etherchannel: { summary: L },
      standby: { brief: L }, vrrp: { brief: L }, power: { inline: L },
    },
    ping: L, traceroute: L,
  },
  juniper: {
    show: {
      interfaces: { terse: L, descriptions: L, extensive: L, statistics: L },
      route: { summary: L, protocol: { bgp: L, ospf: L, static: L, direct: L }, table: L },
      bgp: { summary: L, neighbor: L, group: L }, ospf: { neighbor: L, interface: L, database: L },
      isis: { adjacency: L }, lldp: { neighbors: L }, arp: { "no-resolve": L }, vlans: L,
      "ethernet-switching": { table: L, interfaces: L }, lacp: { interfaces: L },
      system: { uptime: L, alarms: L, users: L, storage: L, processes: { extensive: L } },
      chassis: { hardware: L, alarms: L, environment: L, "routing-engine": L, fpc: L },
      log: { messages: L }, version: L, configuration: L, ntp: { status: L, associations: L },
      security: { flow: { session: L }, zones: L, policies: L },
    },
    ping: L, traceroute: L,
  },
  mikrotik: {
    "/ip": {
      address: RO, route: RO, arp: RO, pool: RO, neighbor: RO, service: RO, "dhcp-client": RO,
      "dhcp-server": { ...RO, lease: RO }, dns: { ...RO, cache: RO },
      firewall: { filter: RO, nat: RO, mangle: RO, "address-list": RO, connection: RO },
      ipsec: { "active-peers": RO, policy: RO },
    },
    "/interface": {
      ...RO, ethernet: RO, vlan: RO, bonding: RO, list: RO, bridge: { ...RO, port: RO, host: RO },
      wireless: { ...RO, "registration-table": RO }, wifi: { ...RO, "registration-table": RO }, wireguard: { ...RO, peers: RO },
    },
    "/system": { resource: RO, identity: RO, routerboard: RO, clock: RO, package: RO, health: RO, license: RO, history: RO },
    "/routing": { route: RO, ospf: { neighbor: RO, instance: RO }, bgp: { session: RO, connection: RO } },
    "/ipv6": { address: RO, route: RO, neighbor: RO },
    "/log": RO, "/ppp": { active: RO }, "/user": { active: RO }, "/export": L,
  },
  huawei: {
    display: {
      version: L, "current-configuration": L, interface: { brief: L, description: L },
      ip: { interface: { brief: L }, "routing-table": L }, arp: L, "mac-address": L, vlan: L,
      lldp: { neighbor: { brief: L } }, bgp: { peer: L }, ospf: { peer: { brief: L } },
      "cpu-usage": L, "memory-usage": L, logbuffer: L, alarm: { active: L }, device: L, clock: L, users: L,
    },
    ping: L, tracert: L,
  },
  fortinet: {
    get: {
      system: { status: L, interface: { physical: L }, performance: { status: L }, arp: L, ha: { status: L } },
      router: { info: { "routing-table": { all: L }, bgp: { summary: L }, ospf: { neighbor: L } } },
      hardware: { status: L, nic: L },
    },
    show: { firewall: { policy: L, address: L }, system: { interface: L } },
    ping: L, traceroute: L,
  },
  linux: {
    ip: { addr: L, route: L, link: L, neigh: L }, ss: { "-tulpn": L }, hostname: L, uname: { "-a": L },
    uptime: L, df: { "-h": L }, free: { "-m": L }, ping: { "-c": L }, traceroute: L, arp: { "-n": L },
    netstat: L, route: { "-n": L }, ifconfig: L,
  },
};
// What may follow "|" (the server only checks the part before the pipe on network OSes).
const TERM_PIPE = {
  cisco: { include: L, exclude: L, begin: L, section: L, count: L },
  juniper: { match: L, except: L, count: L, last: L, "no-more": L, display: { set: L } },
  huawei: { include: L, exclude: L, begin: L, count: L },
  fortinet: { grep: L },
};

function termFamily() {
  const dev = (state.overview?.devices || []).find((d) => d.name === $("#term-dev").value);
  const t = (dev?.type || "").toLowerCase();
  for (const f of ["mikrotik", "juniper", "huawei", "fortinet", "linux"]) if (t.startsWith(f)) return f;
  return "cisco";
}

function termMatches(node, word) {
  const w = word.toLowerCase();
  return Object.keys(node).filter((k) => k.toLowerCase().startsWith(w));
}

// Full keyword for what was typed (exact match wins, then a unique prefix), or null.
function termResolve(node, word) {
  if (!node || !word) return null;
  const w = word.toLowerCase();
  const exact = Object.keys(node).find((k) => k.toLowerCase() === w);
  if (exact) return exact;
  const m = termMatches(node, word);
  return m.length === 1 ? m[0] : null;
}

// Interface names of each device (from /api/interfaces), offered after these keywords.
const termIfaces = {};
const TERM_IF_AFTER = new Set(["interfaces", "interface"]);

function termLoadIfaces() {
  const dev = $("#term-dev").value;
  if (!dev || dev in termIfaces) return;
  termIfaces[dev] = [];
  apiJson(`/api/interfaces?device=${encodeURIComponent(dev)}`)
    .then((r) => { termIfaces[dev] = r.interfaces || []; })
    .catch(() => { delete termIfaces[dev]; });
}

// The node that offers the next word, the word being typed ("" right after a space),
// and every option for it: keywords of the node + the device's interface names after "interface(s)".
function termContext(text) {
  const fam = termFamily();
  const words = text.replace(/^\s+/, "").split(/\s+/);
  const current = words.pop();
  let node = TERM_TREE[fam];
  let prev = "";
  for (const w of words) {
    if (w === "|") { node = TERM_PIPE[fam] || null; prev = "|"; continue; }
    const k = termResolve(node, w);
    node = k ? node[k] : null;
    prev = k || "";
  }
  const ifaces = TERM_IF_AFTER.has(prev) ? termIfaces[$("#term-dev").value] || [] : [];
  const options = [...(node ? Object.keys(node) : []), ...ifaces];
  return { node, current, options, free: !node && !ifaces.length };
}

function termFilter(options, word) {
  const w = word.toLowerCase();
  return options.filter((k) => k.toLowerCase().startsWith(w));
}

// "sh ip int br" -> "show ip interface brief"; unknown words (interface names, IPs, regex) stay as typed.
function termExpand(line) {
  const fam = termFamily();
  let node = TERM_TREE[fam];
  return line.trim().split(/\s+/).map((w) => {
    if (w === "|") { node = TERM_PIPE[fam] || null; return w; }
    const k = termResolve(node, w);
    node = k ? node[k] : null;
    return k || w;
  }).join(" ");
}

function termColumns(words) {
  const width = Math.max(...words.map((w) => w.length)) + 2;
  const perRow = Math.max(1, Math.floor(60 / width));
  const rows = [];
  for (let i = 0; i < words.length; i += perRow) rows.push("  " + words.slice(i, i + perRow).map((w) => w.padEnd(width)).join("").trimEnd());
  return rows.join("\n");
}

function termNoMatch(input) {
  const form = input.closest(".term-form");
  form.classList.add("nomatch");
  setTimeout(() => form.classList.remove("nomatch"), 350);
}

function termSetBefore(input, before, after) {
  input.value = before + after;
  input.setSelectionRange(before.length, before.length);
}

function termTab(input) {
  const before = input.value.slice(0, input.selectionStart ?? input.value.length);
  const after = input.value.slice(input.selectionEnd ?? input.value.length);
  const { current, options } = termContext(before);
  const base = before.slice(0, before.length - current.length);
  const exact = current && options.find((k) => k.toLowerCase() === current.toLowerCase());
  const opts = termFilter(options, current);
  if (exact || opts.length === 1) return termSetBefore(input, `${base}${exact || opts[0]} `, after.replace(/^\s+/, ""));
  if (!opts.length) return termNoMatch(input);
  let prefix = opts[0];
  for (const o of opts) while (!o.toLowerCase().startsWith(prefix.toLowerCase())) prefix = prefix.slice(0, -1);
  if (prefix.length > current.length) return termSetBefore(input, base + prefix, after);
  termWrite(`${$("#term-prompt").textContent} ${before}`, "t-cmd");
  termWrite(termColumns(opts));
}

function termQuestion(input) {
  const before = input.value.slice(0, input.selectionStart ?? input.value.length);
  const { current, options, free } = termContext(before);
  termWrite(`${$("#term-prompt").textContent} ${before}?`, "t-cmd");
  if (free) return termWrite("  <text>   (ინტერფეისი, IP, ფილტრი...)");
  const opts = termFilter(options, current);
  if (opts.length) return termWrite(termColumns(opts));
  termWrite(current ? "% Unrecognized command" : "  <cr>", current ? "t-err" : "");
}

async function openTerminal() {
  if (!state.overview) await loadOverview();
  const sel = $("#term-dev");
  const devices = state.overview?.devices || [];
  const current = sel.value;
  sel.replaceChildren(...devices.map((d) => {
    const o = el("option");
    o.value = d.name;
    o.textContent = `${d.up ? "🟢" : "🔴"} ${d.name} · ${d.host}`;
    return o;
  }));
  if (current) sel.value = current;
  termChips();
  setTimeout(() => $("#term-input").focus(), 50);
}

function termChips() {
  const dev = (state.overview?.devices || []).find((d) => d.name === $("#term-dev").value);
  const type = dev?.type || "";
  const list = type.startsWith("mikrotik") ? TERM_CHIPS.mikrotik : type.startsWith("juniper") ? TERM_CHIPS.juniper : TERM_CHIPS.default;
  $("#term-prompt").textContent = dev ? `${dev.name}${type.startsWith("mikrotik") ? " >" : "#"}` : "#";
  termLoadIfaces();
  $("#term-chips").replaceChildren(...list.map((c) => {
    const b = el("button");
    b.type = "button";
    b.textContent = c;
    b.addEventListener("click", () => runTerm(c));
    return b;
  }));
}

function termWrite(text, cls) {
  const out = $("#term-out");
  const span = el("span", cls || "");
  span.textContent = text + "\n";
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

async function runTerm(cmd) {
  const dev = $("#term-dev").value;
  cmd = cmd.trim();
  if (!dev || !cmd) return;
  termHistory.push(cmd);
  termPos = termHistory.length;
  termWrite(`${$("#term-prompt").textContent} ${cmd}`, "t-cmd");
  try {
    const r = await apiJson("/api/command", { method: "POST", json: { line: `/cmd ${dev} ${cmd}` } });
    const text = (r.text || r.error || "").replace(/^📟.*\n/, "").replace(/```\w*\n?/g, "").trim();
    termWrite(text || "(ცარიელი პასუხი)", /^(⚠️|⛔)/.test(text) ? "t-err" : "");
  } catch (err) {
    termWrite(`⚠️ ${err.message}`, "t-err");
  }
}

function showLogin(info = {}) {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#totp-row").hidden = !info.totp;
  $("#login-setup").hidden = info.configured !== false;
  $("#password").focus();
}

function showWho(me) {
  if (!me?.user) return;
  const role = me.role === "viewer" ? "მხოლოდ ნახვა" : "ადმინი";
  $("#whoami").textContent = `შესული ხარ როგორც: ${me.user} · ${role}`;
}

function showApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
  watchConsole();
  apiJson("/api/me").then(showWho).catch(() => {});
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
  startI18n();
  document.querySelectorAll("#lang button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));
  load();
  renderQuick();
  setupVoice();
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch((e) => console.warn("service worker:", e.message));

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
      const res = await api("/api/login", { method: "POST", json: {
        username: $("#username").value.trim(), password: $("#password").value, totp: $("#totp").value } });
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
    if (state.busy && (state.attachments.length || state.queue.length >= MAX_QUEUE)) {
      toast("მოიცადე — წინა ბრძანება ჯერ სრულდება");  // keep the typed text: it cannot be queued now
      return;
    }
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
  $("#term-dev").addEventListener("change", termChips);
  $("#term-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("#term-input");
    runTerm(termExpand(input.value));
    input.value = "";
  });
  $("#term-input").addEventListener("beforeinput", (e) => {
    // "?" shows the options instead of being typed, like on Cisco/MikroTik.
    if (e.data === "?") { e.preventDefault(); termQuestion(e.target); }
  });
  // Phones have no Tab key: the Tab button does the same. pointerdown keeps the keyboard open.
  $("#term-tab").addEventListener("pointerdown", (e) => e.preventDefault());
  $("#term-tab").addEventListener("click", () => { const i = $("#term-input"); i.focus(); termTab(i); });
  $("#term-input").addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey) { e.preventDefault(); termTab(e.target); return; }
    if (e.key === "ArrowUp" && termPos > 0) { termPos -= 1; e.target.value = termHistory[termPos]; e.preventDefault(); }
    if (e.key === "ArrowDown") { termPos = Math.min(termHistory.length, termPos + 1); e.target.value = termHistory[termPos] || ""; }
  });
  const initial = new URLSearchParams(location.search).get("view");
  if (initial && VIEW_TITLES[initial] && initial !== "term") state.view = initial;
  if (state.view === "term") state.view = "chat";  // the Terminal tab was removed
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
  $("#dash-refresh").addEventListener("click", () => { loadOverview(); if (state.view === "dash") loadMap(); });
  $("#map-refresh").addEventListener("click", () => loadMap(true));
  $("#con-refresh").addEventListener("click", () => loadConsole());
  document.querySelectorAll("#bw-period button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#bw-period button").forEach((x) => x.classList.toggle("on", x === b));
    bw.period = b.dataset.p;
    loadBandwidth();
  }));
  $("#hw-refresh").addEventListener("click", () => { loadHw(true); loadSysinfo(true); });
  $("#ss-start").addEventListener("click", () => {
    const opt = $("#ss-disk").selectedOptions[0];
    if (!opt) return;
    if (!confirm("კომპიუტერზე Windows ადმინის დადასტურებას (UAC) ითხოვს. დისკი მხოლოდ წაიკითხება. დავიწყო?")) return;
    apiJson("/api/surfscan/start", { method: "POST", json: { disk: Number(opt.value), label: opt.textContent } })
      .then(() => { toast("🖥 კომპიუტერზე დააჭირე „Yes“ (UAC)"); setTimeout(loadSurf, 800); }).catch((e) => toast(e.message));
  });
  $("#ss-stop").addEventListener("click", () => apiJson("/api/surfscan/stop", { method: "POST", json: {} }).then(() => setTimeout(loadSurf, 800)).catch((e) => toast(e.message)));
  $("#ss-chkdsk").addEventListener("click", () => {
    if (!confirm("chkdsk C: /scan — კომპიუტერზე UAC-ის დადასტურება საჭიროა. გავუშვა?")) return;
    apiJson("/api/surfscan/chkdsk", { method: "POST", json: { drive: "C" } }).then(() => {
      toast("🖥 კომპიუტერზე დააჭირე „Yes“ (UAC)");
      const poll = async (n) => {
        const r = await apiJson("/api/surfscan?chkdsk=C").catch(() => ({}));
        if (r.text) { const pre = $("#ss-chk"); pre.hidden = false; pre.textContent = r.text.trim().slice(-2500); return; }
        if (n > 0 && state.view === "hw") setTimeout(() => poll(n - 1), 4000);
      };
      poll(60);
    }).catch((e) => toast(e.message));
  });
  const mtAction = (action, json = {}) => apiJson(`/api/memtest/${action}`, { method: "POST", json })
    .then(() => setTimeout(loadMemtest, 400)).catch((e) => toast(e.message));
  $("#mt-quick").addEventListener("click", () => mtAction("start", { mode: "quick" }));
  $("#mt-full").addEventListener("click", () => mtAction("start", { mode: "full" }));
  $("#mt-stop").addEventListener("click", () => mtAction("stop"));
  $("#mt-reboot").addEventListener("click", () => {
    if (confirm("კომპიუტერზე გაიხსნება Windows Memory Diagnostic (საჭიროა დადასტურება და გადატვირთვა). გავხსნა?")) {
      mtAction("reboot").then(() => toast("🖥 ფანჯარა გაიხსნა კომპიუტერზე"));
    }
  });
  document.querySelectorAll("#dz-mode button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#dz-mode button").forEach((x) => x.classList.toggle("on", x === b));
    $("#dz-grid-pane").hidden = b.dataset.mode !== "grid";
    $("#dz-walk-pane").hidden = b.dataset.mode !== "walk";
    if (b.dataset.mode !== "walk") dzWalkStop();
  }));
  const dzSize = () => dzPost("size", { cols: Number($("#dz-cols").value), rows: Number($("#dz-rows").value) }).catch((e) => toast(e.message));
  $("#dz-cols").addEventListener("change", dzSize);
  $("#dz-rows").addEventListener("change", dzSize);
  $("#dz-clear").addEventListener("click", () => { if (confirm("გავასუფთავო მკვდარი ზონების რუკა?")) dzPost("clear", {}).catch(() => {}); });
  $("#dz-walk-go").addEventListener("click", () => (dz.walk ? dzWalkStop() : dzWalkStart()));
  $("#dz-router").addEventListener("click", (e) => {
    dz.routerMode = !dz.routerMode;
    e.currentTarget.classList.toggle("on", dz.routerMode);
    if (dz.routerMode) toast("დააჭირე უჯრას, სადაც როუტერი დგას");
  });
  $("#dz-mark").addEventListener("click", dzMark);
  $("#rooms-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const room = $("#room-name").value.trim();
    if (room) measureRoom(room);
  });
  document.querySelectorAll("#dev-filter button").forEach((b) => b.addEventListener("click", () => {
    state.devFilter = b.dataset.filter;
    document.querySelectorAll("#dev-filter button").forEach((x) => x.classList.toggle("on", x === b));
    renderDevices();
  }));
  $("#dev-search").addEventListener("input", (e) => { state.devSearch = e.target.value; renderDevices(); });

  // Live Devices
  $("#live-search").addEventListener("input", (e) => { live.search = e.target.value; renderLive(); });
  document.querySelectorAll(".live-table th button").forEach((b) => b.addEventListener("click", () => {
    live.dir = live.sort === b.dataset.sort ? -live.dir : 1;
    live.sort = b.dataset.sort;
    renderLive();
  }));
  $("#live-iface").addEventListener("change", (e) => liveSetting({ interface: e.target.value }));
  $("#live-interval").addEventListener("change", (e) => liveSetting({ ping_interval: Number(e.target.value) }));
  document.querySelectorAll("#live-filter button").forEach((b) => b.addEventListener("click", () => {
    live.filter = b.dataset.filter;
    document.querySelectorAll("#live-filter button").forEach((x) => x.classList.toggle("on", x === b));
    renderLive();
  }));
  $("#live-alert-unknown").addEventListener("change", (e) => liveSetting({ alert_unknown: e.target.checked }));
  $("#live-night").addEventListener("change", (e) => liveSetting({ night_alerts: e.target.checked }));
  $("#live-night-window").addEventListener("change", (e) => {
    const v = e.target.value.replace(/\s/g, "");
    if (!/^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/.test(v)) { toast("ფორმატი: 00:00-07:00"); return; }
    liveSetting({ night: v });
  });
  $("#live-trust-all").addEventListener("click", () => {
    if (!confirm("ყველა ახლანდელი მოწყობილობა მოვნიშნო ნაცნობად?")) return;
    apiJson("/api/live/trust", { method: "POST", json: { all: true } })
      .then((r) => { toast(`${r.count} მოწყობილობა — ნაცნობია`); loadLive(); }).catch((e) => toast(e.message));
  });
  $("#live-iot").addEventListener("click", () => runIotCheck());
  $("#live-scan").addEventListener("click", () => apiJson("/api/live/scan", { method: "POST", json: {} })
    .then(() => { toast("სკანირება დაიწყო"); setTimeout(loadLive, 1500); })
    .catch((e) => toast(e.message)));
  document.addEventListener("visibilitychange", () => { if (!document.hidden && state.view === "live") startLive(); });

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
  setInterval(() => {
    if (document.hidden || $("#app").hidden) return;
    loadOverview();
    if (state.view === "dash") loadMap();  // live up/down and link load on the map
  }, 60_000);

  const me = await apiJson("/api/me").catch(() => ({}));
  if (me.authenticated) showApp();
  else showLogin(me);
}

init();
