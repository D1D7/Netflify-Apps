// English interface for NetAgent. Georgian is the source language; with English selected (Settings → Language)
// the app's own texts (buttons, titles, tables, toasts) are translated as they appear on screen. Answers from
// the server (chat messages, terminal output) are shown as they come.
const LANG_KEY = "na.lang";

export function getLang() {
  try { return localStorage.getItem(LANG_KEY) === "en" ? "en" : "ka"; } catch { return "ka"; }
}

export function setLang(lang) {
  try { localStorage.setItem(LANG_KEY, lang); } catch { /* ignore */ }
  location.reload();
}

const EN = {
  // login
  "AI ქსელის ასისტენტი": "AI network assistant", "მომხმარებელი": "User", "(მთავარი ანგარიში — ცარიელი)": "(main account: leave empty)",
  "პაროლი": "Password", "2FA კოდი": "2FA code", "შესვლა": "Sign in", "შესვლა...": "Signing in...",
  "შესვლა ვერ მოხერხდა": "Sign-in failed", "პაროლის ჩვენება": "Show password",
  "პაროლი ჯერ არ არის დაყენებული. სერვერზე გაუშვი:": "No password set yet. On the server run:",
  "🔒 დაცული კავშირი · მხოლოდ შენი ქსელიდან": "🔒 Secure connection · only from your network",
  // tabs and titles
  "ქსელი": "Network", "მოწყობილობები და მოვლენები": "Devices and events", "პარამეტრები": "Settings",
  "აპი და ანგარიში": "App and account", "ტერმინალი": "Terminal", "read-only ბრძანებები მოწყობილობებზე": "Read-only device commands",
  "ვინ არის ქსელში ახლა": "Who is on the network now", "ჩატი": "Chat", "ჩატი და ქსელი ერთად": "Chat and network together",
  // chat
  "ქსელის სტატუსი": "Network status", "ფოტო ან ფაილი": "Photo or file", "მკითხე რამე ან დაწერე /status": "Ask anything or type /status",
  "მკითხე რამე…": "Ask anything…", "ხმით კითხვა": "Ask by voice", "გაგზავნა": "Send", "გამარჯობა 👋": "Hello 👋",
  "მკითხე რამე ქსელზე, გამომიგზავნე ფოტო ან config ფაილი.": "Ask anything about your network, or send a photo or a config file.",
  "როგორაა ქსელი? რომელიმე მოწყობილობა ხომ არ არის გათიშული?": "How is the network? Is any device down?",
  "R1-ის ინტერფეისების IP-ები მაჩვენე": "Show me R1's interface IPs",
  "რომელი IP-ებია თავისუფალი 192.168.1.0/24-ში?": "Which IPs are free in 192.168.1.0/24?",
  "რამდენად უსაფრთხოა ქსელი?": "How secure is the network?",
  "ვფიქრობ...": "Thinking...", "ვამუშავებ...": "Processing...", "ვასრულებ...": "Running...", "კოპირება": "Copy",
  "კოპირება ვერ მოხერხდა": "Copy failed", "წაშლა": "Remove", "მაქსიმუმ 5 ფაილი": "5 files at most",
  "მოიცადე — წინა ბრძანება ჯერ სრულდება": "Wait: the previous command is still running",
  "კავშირი გაწყდა — სცადე თავიდან": "Connection lost: try again", "PIN ცვლილების დასადასტურებლად:": "PIN to confirm the change:",
  "მიკროფონზე წვდომა არ არის დაშვებული": "Microphone access is not allowed", "ხმის ამოცნობა ვერ მოხერხდა": "Voice recognition failed",
  "Excel ფაილი": "Excel file", "სურათი": "Image", "ტექსტური ფაილი": "Text file",
  // quick actions
  "სწრაფი მოქმედებები": "Quick actions", "სწრაფი ბრძანებები": "Quick commands", "სტატუსი": "Status",
  "დიაგნოსტიკა": "Diagnose", "ინტერნეტი": "Internet", "ქსელის სკანი": "Network scan", "ჟურნალი": "Activity",
  "რეპორტი": "Report", "აუდიტი": "Audit", "დაცვა": "Security", "ქვიზი": "Quiz", "რუკა": "Map", "ლოგები": "Logs",
  "შენიშვნები": "Notes", "ბრძანებები": "Commands", "დემო სცენარები": "Demo scenarios", "Wi-Fi არხები": "Wi-Fi channels",
  "სერვისები": "Services", "DNS ბლოკი": "DNS blocking", "დილის შეჯამება": "Morning summary",
  // network tab
  "სრულად": "Full view", "ონლაინ": "online", "LIVE მონიტორინგი": "LIVE monitoring", "ქსელის რუკა": "Network map",
  "კაბელების განახლება": "Rediscover cables", "გათიშული": "down", "გარე მეზობელი": "External neighbour",
  "დატვირთვა <50%": "Load <50%", "მოწყობილობები": "Devices", "ყველა": "All", "ბოლო მოვლენები": "Recent events",
  "ძებნა: სახელი, IP, საიტი": "Search: name, IP, site", "ახლახან": "just now",
  "✅ ყველა მოწყობილობა ხელმისაწვდომია": "✅ All devices are reachable", "ვერაფერი მოიძებნა": "Nothing found",
  "მიუწვდომელი · timeout": "Unreachable · timeout", "მიუწვდომელი": "Unreachable", "მოწყობილობები ჯერ არ არის": "No devices yet",
  "ყველაფერი რიგზეა": "All good", "გათიშ.": "Down", "24 სთ": "24 h", "ახლა": "Now", "მიგნება 24 სთ": "Findings 24 h",
  "ალერტები": "Alerts", "მოვლენები ჯერ არ ყოფილა.": "No events yet.", "სიჩქარე: /speedtest": "Speed: /speedtest",
  "🔴 არ არის": "🔴 Down", "კაბელები განახლდა": "Cables rediscovered",
  "რუკისთვის საჭიროა მართვადი როუტერები/switch-ები devices.yaml-ში (კაბელებს CDP/LLDP-ით ვპოულობ).":
    "The map needs managed routers/switches in devices.yaml (cables are found with CDP/LLDP).",
  "გათიშულია": "Down", "გარე მეზობელი (inventory-ში არ არის)": "External neighbour (not in the inventory)",
  "ჯანმრთელობა": "Health", "შემოწმება": "Check",
  // settings
  "შეტყობინებები": "Notifications", "Push შეტყობინებები": "Push notifications", "სატესტო შეტყობინება": "Test notification",
  "გამოგიგზავნის შემოწმებისთვის": "Sends you one to check", "გარეგნობა": "Appearance", "თემა": "Theme", "ავტო": "Auto",
  "ღია": "Light", "მუქი": "Dark", "ენა": "Language", "აპის დაინსტალირება": "Install the app",
  "მთავარ ეკრანზე, როგორც ჩვეულებრივი აპი": "On the home screen, like a normal app", "AI ხარჯი": "AI cost",
  "საუბარი": "Conversation", "საუბრის გასუფთავება": "Clear conversation", "შლის ისტორიას ამ ტელეფონზე": "Deletes the history on this phone",
  "ანგარიში": "Account", "გასვლა": "Sign out", "გასვლა ყველა მოწყობილობიდან": "Sign out everywhere",
  "გააუქმებს ყველა სესიას": "Ends every session", "მხოლოდ ნახვა": "view only", "ადმინი": "admin",
  "ჩართულია — ალერტები ამ მოწყობილობაზე მოვა": "On: alerts will arrive on this device", "გამორთულია": "Off",
  "მიუწვდომელია: ამ ბრაუზერმა service worker ვერ ჩატვირთა (სცადე Chrome ან დაინსტალირებული აპი)":
    "Unavailable: this browser could not load the service worker (try Chrome or the installed app)",
  "მიუწვდომელია ამ ბრაუზერში (საჭიროა HTTPS, მაგ. Tailscale)": "Unavailable in this browser (needs HTTPS, e.g. Tailscale)",
  "შეტყობინებები გამოირთო": "Notifications turned off", "ნებართვა არ მოგეცა — ჩართე აპის პარამეტრებში": "Permission denied: allow it in the app settings",
  "🔔 შეტყობინებები ჩაირთო": "🔔 Notifications on", "გაიგზავნა — შეამოწმე შეტყობინებები": "Sent: check your notifications",
  "ვერ გაიგზავნა": "Could not send", "გავასუფთავო საუბარი?": "Clear the conversation?", "საუბარი გასუფთავდა": "Conversation cleared",
  "გამოვიდე ყველა მოწყობილობიდან?": "Sign out of every device?",
  // live devices
  "ინტერფეისი": "Interface", "ქსელის ინტერფეისი": "Network interface", "განახლება": "Refresh", "განახლების ინტერვალი": "Refresh interval",
  "2 წმ": "2 s", "3 წმ": "3 s", "5 წმ": "5 s", "10 წმ": "10 s", "30 წმ": "30 s", "სკანი ახლა": "Scan now",
  "ძებნა: IP, MAC, სახელი, ტიპი": "Search: IP, MAC, name, type", "შეტყობინებები, ნაცნობები, IoT": "Alerts, trusted devices, IoT",
  "უცნობი მოწყობილობის შემოსვლაზე შეტყობინება": "Alert when an unknown device joins", "ღამის რეჟიმი: ამ დროს": "Night mode: at this time alert on",
  "ნებისმიერის": "any", "შემოსვლაზე შეტყობინება": "device joining", "ღამე:": "Night:", "ყველა ახლანდელი — ნაცნობია": "Trust everything here now",
  "IoT უსაფრთხოების შემოწმება": "IoT security check", "უცნობი": "Unknown", "მწარმოებელი": "Vendor", "სახელი": "Name",
  "პირველად": "First seen", "ბოლოს": "Last seen", "მოვლენები": "Events", "მოწყობილობა": "Device",
  "ინტერფეისი არ არის": "No interface", "სკანირება...": "Scanning...", "პირველი სკანი...": "First scan...",
  "ვეძებ მოწყობილობებს...": "Looking for devices...", "მოწყობილობა ვერ ვიპოვე": "No device found", "ეს PC": "This PC",
  "როუტერი": "Router", "დაიკარგა": "lost", "შემოსვლა/გასვლა ჯერ არ დაფიქსირებულა.": "No joins or leaves yet.",
  "ახალი მოწყობილობა შემოვიდა": "New device joined", "დაბრუნდა ქსელში": "Came back", "გავიდა ქსელიდან": "Left the network",
  "ეს ping დაიკარგა, მაგრამ ARP-ზე პასუხობს — ქსელშია": "This ping was lost, but it answers ARP: it is on the network",
  "ping-ს არ პასუხობს (firewall), მაგრამ ARP-ზე პასუხობს — ქსელშია": "No ping reply (firewall), but it answers ARP: it is on the network",
  "დახურვა": "Close", "ონლაინ ისტორია": "Online history", "7 დღე": "7 days", "ღია პორტები": "Open ports",
  "სახელის მიცემა": "Give a name", "მინ.": "Min", "საშ.": "Avg", "მაქს.": "Max", "ტიპი": "Type", "ნაცნობი (შენი)": "Trusted (yours)",
  "ღია პორტი არ ჩანს": "No open ports seen", "ქსელის სახელი": "Network name", "ვერ გაირკვა (DNS, NetBIOS, mDNS)": "Unknown (DNS, NetBIOS, mDNS)",
  "ნაცნობებიდან მოხსნა": "Remove from trusted", "ჩემია (ნაცნობი)": "It's mine (trusted)", "მოიხსნა ნაცნობებიდან": "Removed from trusted",
  "მოინიშნა ნაცნობად": "Marked as trusted", "შენახულია": "Saved", "სკანირება დაიწყო": "Scan started",
  "ფორმატი: 00:00-07:00": "Format: 00:00-07:00", "ყველა ახლანდელი მოწყობილობა მოვნიშნო ნაცნობად?": "Mark every current device as trusted?",
  "ეს კომპიუტერი": "This computer", "კომპიუტერი": "Computer", "ტელეფონი / პლანშეტი": "Phone / tablet",
  "ტელევიზორი / მედია": "TV / media", "პრინტერი": "Printer", "კამერა": "Camera", "ჭკვიანი სახლი (IoT)": "Smart home (IoT)",
  "NAS / სერვერი": "NAS / server", "ქსელური მოწყობილობა": "Network device", "სათამაშო კონსოლი": "Game console",
  "ტიპი უცნობია": "Unknown type", "შემთხვევითი MAC (ტელეფონის/ლეპტოპის privacy რეჟიმი)": "Random MAC (phone/laptop privacy mode)",
  "უცნობი მოწყობილობა ქსელში": "Unknown device on the network", "ახალი შესვლა": "New sign-in",
  "კი": "Yes", "არა": "No", "ჰო": "Yes", "ავტომატური": "Automatic", "(ვირტუალური)": "(virtual)",
  // terminal
  "Tab — სიტყვის დასრულება": "Tab: complete the word", "გაშვება": "Run", "(ცარიელი პასუხი)": "(empty answer)",
  "Tab — სიტყვის დასრულება · ? — ვარიანტები · შემოკლება მუშაობს (sh ip int br). მხოლოდ წაკითხვა: show / print / ping.":
    "Tab: complete the word · ?: options · abbreviations work (sh ip int br). Read-only: show / print / ping.",
};

// texts with numbers or names inside
const PATTERNS = [
  [/^(\d+) წთ წინ$/, "$1 min ago"], [/^(\d+) სთ წინ$/, "$1 h ago"], [/^(\d+) წმ წინ$/, "$1 s ago"],
  [/^(\d+)% ჯანმრთელი$/, "$1% healthy"], [/^განახლდა (.+)$/, "Updated $1"],
  [/^● (\d+) ონლაინ$/, "● $1 online"], [/^● (\d+) ოფლაინ$/, "● $1 offline"], [/^უცნობი \((\d+)\)$/, "Unknown ($1)"],
  [/^(\d+) ონლაინ · (\d+) გათიშული · კაბელები: (\d+)(.*)$/, "$1 online · $2 down · cables: $3$4"],
  [/^ჩამოტვირთვა (.+) · ატვირთვა (.+) Mbps$/, "Download $1 · upload $2 Mbps"],
  [/^Offline · (\d+) პასუხი გამოტოვა$/, "Offline · missed $1 replies"], [/^დანაკარგი (.+)% \((\d+) გაზომვა\)$/, "Loss $1% ($2 samples)"],
  [/^ონლაინ: (.+) სთ ბოლო 24 სთ-ში$/, "Online: $1 h in the last 24 h"], [/^ონლაინ: (.+) სთ ბოლო 7 დღეში$/, "Online: $1 h in the last 7 days"],
  [/^IoT შემოწმება · (.+)$/, "IoT check · $1"], [/^(.+) · ჩამოტვირთვა$/, "$1 · download"], [/^რიგშია: (.+)$/, "Queued: $1"],
  [/^NetAgent · მოდელი: (.+)$/, "NetAgent · model: $1"], [/^ონლაინ(.*)$/, "Online$1"], [/^ავტომატური(.*)$/, "Automatic$1"],
  [/^მინ\. (.+)$/, "Min $1"], [/^საშ\. (.+)$/, "Avg $1"], [/^მაქს\. (.+)$/, "Max $1"],
  [/^(\d+) გათიშულია$/, "$1 down"], [/^გათიშვები 24 სთ: (\d+)$/, "Outages 24 h: $1"], [/^აღმოჩენილია (.+)$/, "discovered $1"],
  [/^(.+) \(ვირტუალური\)$/, "$1 (virtual)"], [/^სკანი (\d+) წმ წინ$/, "Scanned $1 s ago"],
  [/^შესული ხარ როგორც: (.+) · მხოლოდ ნახვა$/, "Signed in as: $1 · view only"], [/^შესული ხარ როგორც: (.+) · ადმინი$/, "Signed in as: $1 · admin"],
  [/^შესული ხარ როგორც: (.+)$/, "Signed in as: $1"],
  [/^გავიდა ქსელიდან: (.+)$/, "Left the network: $1"], [/^ახალი მოწყობილობა შემოვიდა: (.+)$/, "New device joined: $1"],
  [/^დაბრუნდა ქსელში: (.+)$/, "Came back: $1"], [/^პირველად შევიდა: (.+)$/, "First sign-in from: $1"],
  [/^თუ ეს შენ\/თქვენ არ ხართ: (.+)$/, "If this was not you: $1"],
  [/^დღეს: (\S+) — (\d+) მოთხოვნა$/, "Today: $1 · $2 requests"], [/^გუშინ: (.+)$/, "Yesterday: $1"],
  [/^ამ თვეში: (.+)$/, "This month: $1"], [/^დღიური ლიმიტი: (\S+) \(დარჩა (\S+)\)$/, "Daily limit: $1 ($2 left)"],
  [/^(\d+) წმ$/, "$1 s"], [/^(\d+) წთ$/, "$1 min"], [/^(\d+) სთ$/, "$1 h"],
];

const KA = /[Ⴀ-ჿ]/;
const SKIP = ".msg.user, .msg .md, .msg .buttons, pre, code, #term-out, [data-no-i18n]";  // server answers stay as sent

export function t(text) {
  if (text == null || !KA.test(text)) return text;
  const s = String(text);
  const core = s.trim();
  if (EN[core] != null) return s.replace(core, EN[core]);
  for (const [re, to] of PATTERNS) if (re.test(core)) return s.replace(core, core.replace(re, to));
  // a sentence built from several known parts ("… · …")
  if (core.includes(" · ")) {
    const parts = core.split(" · ").map((p) => EN[p.trim()] ?? PATTERNS.reduce((acc, [re, to]) => (re.test(acc) ? acc.replace(re, to) : acc), p));
    return s.replace(core, parts.join(" · "));
  }
  return s;
}

const ATTRS = ["placeholder", "title", "aria-label"];

function fixAttrs(el) {
  for (const a of ATTRS) {
    const v = el.getAttribute(a);
    if (v && KA.test(v)) {
      const w = t(v);
      if (w !== v) el.setAttribute(a, w);
    }
  }
}

function fixText(n) {
  if (!KA.test(n.nodeValue)) return;
  const v = t(n.nodeValue);
  if (v !== n.nodeValue) n.nodeValue = v;
}

function translateNode(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    if (node.parentElement && !node.parentElement.closest(SKIP)) fixText(node);
    return;
  }
  if (node.nodeType !== Node.ELEMENT_NODE || node.closest(SKIP)) return;
  fixAttrs(node);
  const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
    acceptNode: (n) => (n.nodeType === Node.ELEMENT_NODE && n.matches(SKIP) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
  });
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (n.nodeType === Node.ELEMENT_NODE) fixAttrs(n);
    else fixText(n);
  }
}

export function startI18n() {
  const lang = getLang();
  document.documentElement.lang = lang;
  document.querySelectorAll("#lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === lang));
  if (lang !== "en") return;
  document.title = t(document.title);
  translateNode(document.body);
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === "characterData") translateNode(r.target);
      else if (r.type === "attributes") translateNode(r.target);
      else r.addedNodes.forEach(translateNode);
    }
  }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  const confirm0 = window.confirm.bind(window);
  window.confirm = (m) => confirm0(t(m));
  const prompt0 = window.prompt.bind(window);
  window.prompt = (m, d) => prompt0(t(m), d);
}
