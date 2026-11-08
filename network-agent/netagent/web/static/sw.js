// NetAgent service worker: app shell cache + push notifications.
const CACHE = "netagent-shell-v13";
const SHELL = [
  "/",
  "/static/app.css",
  "/static/app.js",
  "/manifest.webmanifest",
  "/static/icon-192.png",
  "/static/icon-512.png",
  "/static/logo.svg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Network first for the shell (so updates apply immediately), cache as offline fallback.
// API calls are never cached: they carry live network data.
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (res.ok && SHELL.includes(url.pathname)) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(event.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(event.request).then((r) => r || caches.match("/"))),
  );
});

self.addEventListener("push", (event) => {
  let data = { title: "NetAgent", body: "", tag: "netagent", url: "/" };
  try {
    data = { ...data, ...event.data.json() };
  } catch {
    if (event.data) data.body = event.data.text();
  }
  event.waitUntil((async () => {
    await self.registration.showNotification(data.title, {
      body: data.body,
      tag: data.tag,
      renotify: true,
      icon: "/static/icon-192.png",
      badge: "/static/badge-96.png",
      data: { url: data.url },
    });
    const clients = await self.clients.matchAll({ type: "window" });
    for (const c of clients) c.postMessage({ type: "alert" });
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = event.notification.data?.url || "/";
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of clients) {
      if ("focus" in c) return c.focus();
    }
    return self.clients.openWindow(target);
  })());
});
