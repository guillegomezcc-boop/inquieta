/* Inquieta Entrenamientos · service worker: guarda la app en el celular para que abra sin internet.
   build_app.py cambia VERSION en cada entrega; el celular baja la versión nueva solo y la usa la próxima vez que se abra.
   Las fotos de los ejercicios (/api/img/…) se guardan aparte y no se borran al cambiar de versión. */
const VERSION = "3.0.1";
const CACHE = 'inquieta-entrena-' + VERSION;
const FOTOS = 'fotos-inquieta';
const ARCHIVOS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./img/apple-touch-icon.png",
  "./img/favicon.png",
  "./img/icon-192.png",
  "./img/icon-512.png",
  "./img/icon-maskable-512.png",
  "./fonts/montserrat-latin-600-normal.woff2",
  "./fonts/montserrat-latin-700-normal.woff2",
  "./fonts/montserrat-latin-800-normal.woff2"
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ARCHIVOS.map((u) => new Request(u, { cache: 'reload' }))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k.startsWith('inquieta-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (/\/api\/img\/[a-f0-9]{32}$/.test(url.pathname)) {
    e.respondWith(caches.open(FOTOS).then((c) => c.match(req.url).then((r) => r || fetch(req).then((res) => {
      if (res.ok) c.put(req.url, res.clone());
      return res;
    }))));
    return;
  }
  if (url.origin !== self.location.origin || url.pathname.includes('/api/')) return;
  const raiz = new URL(self.registration.scope).pathname;
  if (req.mode === 'navigate') {
    if (url.pathname === raiz || url.pathname === raiz + 'index.html') e.respondWith(caches.match('./index.html').then((r) => r || fetch(req)));
    return;
  }
  e.respondWith(caches.match(req, { ignoreSearch: true }).then((r) => r || fetch(req)));
});
