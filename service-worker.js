
const CACHE_NAME = "baytna-static-v1";

self.addEventListener("install", event => {
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    (async () => {
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", event => {
  // لا نخزن صفحات الحسابات أو الصور الخاصة أو طلبات API.
  // تبقى الطلبات متصلة بالخادم مباشرة.
});
