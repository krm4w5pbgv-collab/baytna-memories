const CACHE_NAME = "baytna-memories-v1";

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  // لا نخزّن الصفحات أو بيانات الحسابات الخاصة.
  // نترك المتصفح يتعامل مع الطلبات بشكل طبيعي.
});
