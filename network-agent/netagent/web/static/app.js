// NetAgent app (vanilla JS, no build step)
const $ = (sel) => document.querySelector(sel);
const STORE_KEY = "na.chat.v1";
const MAX_STORED = 200;

const state = {
  messages: [],
  attachments: [],
  busy: false,
  installPrompt: null,
  view: "chat",
};

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
    showLogin();
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

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function inline(s) {
  return esc(s)
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])_([^_\n]+)_(?=[\s).,!?]|$)/g, "$1<em>$2</em>");
}

function md(text) {
  const lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let i = 0;
  const isTableSep = (l) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l);
  const cells = (l) => l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line.trim())) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) buf.push(lines[i++]);
      i++;
      out.push(`<pre><code>${esc(buf.join("\n"))}</code></pre>`);
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
    if (/^\s*([-*•]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\s*\d+[.)]/.test(line);
      const items = [];
      while (i < lines.length && /^\s*([-*•]|\d+[.)])\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*([-*•]|\d+[.)])\s+/, ""));
        i++;
      }
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>${items.map((it) => `<li>${inline(it)}</li>`).join("")}</${tag}>`);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^```/.test(lines[i].trim()) && !/^#{1,6}\s/.test(lines[i])
           && !/^\s*([-*•]|\d+[.)])\s+/.test(lines[i]) && !(lines[i].includes("|") && isTableSep(lines[i + 1] || ""))) {
      para.push(inline(lines[i++]));
    }
    out.push(`<p>${para.join("<br>")}</p>`);
  }
  return out.join("");
}

// ---------------------------------------------------------------- chat rendering

function save() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(state.messages.slice(-MAX_STORED)));
  } catch { /* storage full or disabled: chat still works in memory */ }
}

function load() {
  try {
    state.messages = JSON.parse(localStorage.getItem(STORE_KEY) || "[]");
  } catch {
    state.messages = [];
  }
}

function timeLabel(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString("ka-GE", { hour: "2-digit", minute: "2-digit" });
}

function fileUrl(name, download = false) {
  return `/api/files/${encodeURIComponent(name)}${download ? "?download=1" : ""}`;
}

function renderMessage(m) {
  const el = document.createElement("div");
  el.className = `msg ${m.role}${m.alert ? " alert" : ""}`;
  if (m.role === "user") {
    if (m.thumbs?.length) {
      const t = document.createElement("div");
      t.className = "thumbs";
      for (const src of m.thumbs) {
        const img = document.createElement("img");
        img.src = src;
        img.alt = "";
        t.appendChild(img);
      }
      el.appendChild(t);
    }
    if (m.files?.length) {
      const f = document.createElement("div");
      f.className = "small";
      f.textContent = "📎 " + m.files.join(", ");
      el.appendChild(f);
    }
    if (m.text) el.appendChild(document.createTextNode(m.text));
  } else {
    const body = document.createElement("div");
    body.className = "md";
    body.innerHTML = md(m.text);
    el.appendChild(body);
    if (m.image) {
      const img = document.createElement("img");
      img.className = "result";
      img.src = fileUrl(m.image);
      img.alt = m.text || "chart";
      el.appendChild(img);
    }
    for (const name of m.files || []) {
      const a = document.createElement("a");
      a.className = "file-link";
      a.href = fileUrl(name, true);
      a.textContent = `${/\.xlsx$/.test(name) ? "📊" : /\.png$/.test(name) ? "🖼" : "📄"} ${name}`;
      el.appendChild(a);
    }
    if (m.buttons?.length) {
      const b = document.createElement("div");
      b.className = "buttons";
      for (const btn of m.buttons) {
        const x = document.createElement("button");
        x.type = "button";
        x.textContent = btn.label;
        x.addEventListener("click", () => send(btn.command, { silent: false }));
        b.appendChild(x);
      }
      el.appendChild(b);
    }
  }
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = timeLabel(m.ts);
  el.appendChild(meta);
  return el;
}

const EXAMPLES = [
  "როგორაა ქსელი? რომელიმე მოწყობილობა ხომ არ არის გათიშული?",
  "R1-ის ინტერფეისების IP-ები მაჩვენე",
  "რომელი IP-ებია თავისუფალი 192.168.1.0/24-ში?",
  "რამდენად უსაფრთხოა ქსელი?",
];

function renderAll() {
  const box = $("#messages");
  box.replaceChildren();
  if (!state.messages.length) {
    const e = document.createElement("div");
    e.className = "empty";
    e.innerHTML = `<div class="empty-icon">🤖</div><p><strong>გამარჯობა!</strong><br>მკითხე რამე ქსელზე, გამომიგზავნე ფოტო ან config ფაილი.</p>`;
    const ex = document.createElement("div");
    ex.className = "examples";
    for (const q of EXAMPLES) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = q;
      b.addEventListener("click", () => send(q));
      ex.appendChild(b);
    }
    e.appendChild(ex);
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

function pendingBubble() {
  const el = document.createElement("div");
  el.className = "msg bot";
  el.innerHTML = `<div class="typing"><i></i><i></i><i></i></div><ul class="steps"></ul>`;
  $("#messages").appendChild(el);
  scrollDown();
  return {
    step(label) {
      const ul = el.querySelector(".steps");
      ul.querySelectorAll("li").forEach((li) => li.classList.add("done"));
      const li = document.createElement("li");
      li.textContent = label;
      ul.appendChild(li);
      scrollDown();
    },
    remove() { el.remove(); },
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

function setBusy(b) {
  state.busy = b;
  $("#send").disabled = b;
}

async function send(text, { silent = false } = {}) {
  text = (text ?? "").trim();
  const files = state.attachments.slice();
  if ((!text && !files.length) || state.busy) return;
  switchView("chat");
  setBusy(true);
  if (!silent) {
    const thumbs = files.filter((f) => f.preview).map((f) => f.preview);
    const names = files.filter((f) => !f.preview).map((f) => f.file.name);
    addMessage({ role: "user", text, thumbs, files: names });
  }
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
  const pending = pendingBubble();
  try {
    const res = await api("/api/command", { method: "POST", json: { line } });
    const data = await res.json().catch(() => ({}));
    pending.remove();
    if (res.status === 400) return false;
    addMessage({ role: "bot", text: data.text || data.error || "", files: data.files, image: data.image, buttons: data.buttons });
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
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = `${a.preview ? "🖼" : "📄"} ${a.file.name}`;
    const x = document.createElement("button");
    x.type = "button";
    x.textContent = "✕";
    x.setAttribute("aria-label", "წაშლა");
    x.addEventListener("click", () => { state.attachments.splice(idx, 1); renderAttachments(); });
    chip.appendChild(x);
    box.appendChild(chip);
  });
}

async function shrinkImage(file) {
  // Phone photos are large; resize to max 1600px JPEG so uploads are fast and fit API limits.
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
    if (state.attachments.length >= 5) break;
    let preview = null;
    if (file.type.startsWith("image/")) {
      file = await shrinkImage(file);
      preview = await new Promise((r) => {
        const fr = new FileReader();
        fr.onload = () => r(fr.result);
        fr.readAsDataURL(file);
      });
    }
    state.attachments.push({ file, preview });
  }
  renderAttachments();
}

// ---------------------------------------------------------------- dashboard

const QUICK = [
  ["🩺 სტატუსი", "/status"],
  ["📊 რეპორტი", "/report"],
  ["🛡 აუდიტი", "/audit"],
  ["💾 Backup", "/backup"],
  ["📋 მოწყობილობები", "/devices"],
  ["📝 შენიშვნები", "/notes"],
  ["❓ ბრძანებები", "/help"],
];

function renderQuick() {
  for (const target of [$("#quick"), $("#dash-actions")]) {
    target.replaceChildren();
    for (const [label, cmd] of QUICK) {
      if (target.id === "dash-actions" && cmd === "/help") continue;
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", () => send(cmd));
      target.appendChild(b);
    }
  }
}

function ago(ts) {
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60) return "ახლახან";
  if (s < 3600) return `${Math.floor(s / 60)} წთ წინ`;
  if (s < 86400) return `${Math.floor(s / 3600)} სთ წინ`;
  return new Date(ts).toLocaleString("ka-GE", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function loadOverview() {
  try {
    const data = await apiJson("/api/overview");
    const pill = $("#netsum");
    pill.textContent = data.total ? `${data.up === data.total ? "🟢" : "🔴"} ${data.up}/${data.total}` : "—";
    $("#dash-summary").textContent = data.total ? `${data.up}/${data.total} ხელმისაწვდომი` : "inventory ცარიელია";
    $("#dash-sub").textContent = `AI დღეს: $${data.usage.today.toFixed(2)} · თვეში: $${data.usage.month.toFixed(2)}`;
    const devs = $("#devices");
    devs.replaceChildren();
    if (!data.devices.length) {
      const p = document.createElement("p");
      p.className = "muted small";
      p.textContent = "მოწყობილობები არ არის. ჩატში დაწერე: /discover 10.0.0.0/24";
      devs.appendChild(p);
    }
    for (const d of data.devices) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = `device${d.up ? "" : " down"}`;
      const latency = d.up ? (d.latency_ms != null ? `${Math.round(d.latency_ms)} ms` : "up") : d.reason || "down";
      b.innerHTML = `<div class="name"><span class="dot"></span><span></span></div><div class="sub"></div>`;
      b.querySelector(".name span:last-child").textContent = `${d.name}${d.muted ? " 🔕" : ""}${d.watched ? " 👁" : ""}`;
      b.querySelector(".sub").textContent = `${d.host} · ${latency}`;
      b.addEventListener("click", () => send(`/health ${d.name}`));
      devs.appendChild(b);
    }
    const al = $("#alerts");
    al.replaceChildren();
    if (!data.alerts.length) {
      const p = document.createElement("p");
      p.className = "muted small";
      p.textContent = "ალერტები ჯერ არ ყოფილა.";
      al.appendChild(p);
    }
    for (const a of data.alerts.slice(0, 20)) {
      const div = document.createElement("div");
      div.className = "alert-item";
      div.innerHTML = `<div class="when"></div><div class="md"></div>`;
      div.querySelector(".when").textContent = ago(a.ts);
      div.querySelector(".md").innerHTML = md(a.text);
      al.appendChild(div);
    }
    $("#about").textContent = `მოდელი: ${data.model}`;
  } catch (err) {
    if (err.message !== "unauthorized") $("#netsum").textContent = "⚠️";
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
  const sub = await reg.pushManager.getSubscription();
  return { supported: true, reg, sub };
}

async function refreshPushUI() {
  const st = await pushState().catch(() => ({ supported: false }));
  const status = $("#push-status");
  const toggle = $("#push-toggle");
  if (!st.supported) {
    status.textContent = "ამ ბრაუზერში შეტყობინებები არ არის მხარდაჭერილი (საჭიროა HTTPS — მაგ. Tailscale).";
    toggle.disabled = true;
    $("#push-test").disabled = true;
    return;
  }
  const on = !!st.sub && Notification.permission === "granted";
  status.textContent = on ? "ჩართულია — ალერტები ამ მოწყობილობაზე მოვა." : "გამორთულია.";
  toggle.textContent = on ? "გამორთვა" : "ჩართვა";
  toggle.classList.toggle("primary", !on);
  $("#push-test").disabled = !on;
}

async function togglePush() {
  const st = await pushState();
  if (!st.supported) return;
  if (st.sub) {
    await apiJson("/api/push/unsubscribe", { method: "POST", json: { endpoint: st.sub.endpoint } }).catch(() => {});
    await st.sub.unsubscribe();
  } else {
    const perm = await Notification.requestPermission();
    if (perm !== "granted") {
      alert("შეტყობინებების ნებართვა არ მოგეცა. ჩართე ბრაუზერის/აპის პარამეტრებში.");
      return;
    }
    const { key } = await apiJson("/api/push/key");
    const sub = await st.reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8Array(key) });
    await apiJson("/api/push/subscribe", { method: "POST", json: sub.toJSON() });
  }
  await refreshPushUI();
}

// ---------------------------------------------------------------- views & auth

function switchView(name) {
  state.view = name;
  for (const v of ["chat", "dash", "settings"]) $(`#view-${v}`).hidden = v !== name;
  document.querySelectorAll(".tabbar button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  if (name === "dash") loadOverview();
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
  renderAll();
  loadOverview();
  const cmd = new URLSearchParams(location.search).get("cmd");
  if (cmd) {
    history.replaceState(null, "", "/");
    send(cmd);
  }
}

async function init() {
  load();
  renderQuick();
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#login-error").textContent = "";
    const res = await api("/api/login", { method: "POST", json: { password: $("#password").value, totp: $("#totp").value } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      $("#login-error").textContent = data.error || "შესვლა ვერ მოხერხდა";
      return;
    }
    $("#password").value = "";
    $("#totp").value = "";
    showApp();
  });

  $("#composer").addEventListener("submit", (e) => {
    e.preventDefault();
    const text = $("#input").value;
    $("#input").value = "";
    autoGrow();
    send(text);
  });
  const input = $("#input");
  const autoGrow = () => { input.style.height = "auto"; input.style.height = `${Math.min(input.scrollHeight, 140)}px`; };
  input.addEventListener("input", autoGrow);
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

  document.querySelectorAll(".tabbar button").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#netsum").addEventListener("click", () => switchView("dash"));
  $("#dash-refresh").addEventListener("click", loadOverview);
  $("#push-toggle").addEventListener("click", () => togglePush().catch((e) => alert(e.message)));
  $("#push-test").addEventListener("click", () => apiJson("/api/push/test", { method: "POST", json: {} }).catch((e) => alert(e.message)));
  $("#help").addEventListener("click", () => send("/help"));
  $("#clear-chat").addEventListener("click", async () => {
    if (!confirm("გავასუფთავო საუბარი?")) return;
    await apiJson("/api/reset", { method: "POST", json: {} }).catch(() => {});
    state.messages = [];
    save();
    renderAll();
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

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    state.installPrompt = e;
    $("#install-card").hidden = false;
  });
  $("#install").addEventListener("click", async () => {
    if (!state.installPrompt) return;
    state.installPrompt.prompt();
    await state.installPrompt.userChoice;
    state.installPrompt = null;
    $("#install-card").hidden = true;
  });

  navigator.serviceWorker?.addEventListener("message", (e) => {
    if (e.data?.type === "alert") loadOverview();
  });
  setInterval(() => { if (!document.hidden && !$("#app").hidden) loadOverview(); }, 60_000);

  const me = await apiJson("/api/me").catch(() => ({}));
  if (me.authenticated) showApp();
  else showLogin(me);
}

init();
