/* ══════════════════════════════════════════
   PURE MOTION — Service Worker
   Stratégie prudente :
   - /api/*        → JAMAIS de cache (données toujours fraîches)
   - pages HTML    → réseau d'abord, cache en secours (hors ligne)
   - icônes, CSS   → cache d'abord (rapide)
   ══════════════════════════════════════════ */

const CACHE_VERSION = 'pm-v1';
const SHELL = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png'
];

// ── Installation : met en cache la coquille de base ──
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => cache.addAll(SHELL).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

// ── Activation : supprime les anciens caches ──
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Interception des requêtes ──
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Ne touche qu'aux requêtes GET de notre propre domaine
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // ⚠️ JAMAIS de cache pour l'API : les données doivent être fraîches
  if (url.pathname.startsWith('/api/')) return;

  // Pages HTML : réseau d'abord, cache en secours
  const isPage = req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');
  if (isPage) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then((r) => r || caches.match('/')))
    );
    return;
  }

  // Ressources statiques : cache d'abord
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      });
    }).catch(() => undefined)
  );
});
