'use strict';
const CACHE = 'safebase-shell-v5.6.5';
const SHELL = [
  './',
  'index.html',
  'styles.css?v=5.6.5',
  'app.js?v=5.6.5',
  'manifest.webmanifest',
  'icon-180.png',
  'icon-192.png',
  'icon-512.png',
  'safebase-logo.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if(request.method !== 'GET') return;

  const url = new URL(request.url);
  if(url.origin !== self.location.origin) return;

  // HTML navigation is network-first so GitHub deployments become visible quickly.
  // Only navigations receive the offline index fallback.
  if(request.mode === 'navigate'){
    event.respondWith(
      fetch(request, {cache:'no-store'})
        .then(response => {
          if(response && response.ok){
            const copy = response.clone();
            caches.open(CACHE).then(cache => cache.put('index.html', copy));
          }
          return response;
        })
        .catch(() => caches.match('index.html'))
    );
    return;
  }

  // Versioned static assets are cache-first. A failed asset request never receives
  // index.html, avoiding broken JS/CSS responses while offline.
  event.respondWith(
    caches.match(request).then(cached => {
      if(cached) return cached;
      return fetch(request).then(response => {
        if(response && response.ok){
          const copy = response.clone();
          caches.open(CACHE).then(cache => cache.put(request, copy));
        }
        return response;
      });
    })
  );
});
