const VERSION = "campusshield-v9";

const SHELL = [
  "/",
  "/index.html",
  "/css/app.css",
  "/js/app.js",
  "/js/api.js",
  "/js/auth.js",
  "/js/ai.js",
  "/js/ui.js",
  "/js/drawer.js",
  "/js/tools.js",
  "/js/views/assistant.js",
  "/js/views/protection.js",
  "/js/views/threats.js",
  "/js/views/activity.js",
  "/js/views/coverage.js",
  "/js/views/settings.js",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/favicon.svg"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(VERSION)
      .then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => key !== VERSION).map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;

  if (request.method !== "GET") return;

  const url = new URL(request.url);

  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) return;
  if (url.pathname === "/app" || url.pathname.startsWith("/app/")) return;

  event.respondWith(handle(request));
});

async function handle(request) {
  const cached = await caches.match(request);

  if (cached) {
    fetch(request)
      .then(response => {
        if (response.ok) {
          caches.open(VERSION).then(cache => cache.put(request, response.clone()));
        }
      })
      .catch(() => {});
    return cached;
  }

  try {
    const response = await fetch(request);

    if (response.ok) {
      const cache = await caches.open(VERSION);
      cache.put(request, response.clone());
    }

    return response;
  } catch {
    if (request.mode === "navigate") {
      const fallback = await caches.match("/index.html");
      if (fallback) return fallback;
    }

    return new Response("Offline", {
      status: 503,
      headers: { "Content-Type": "text/plain" }
    });
  }
}
