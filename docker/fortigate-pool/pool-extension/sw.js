/* ───────────────────────────────────────────────────────────────────────────
 * sw.js (background service worker) — relay fetch tới navigator.
 * Content script không fetch thẳng được (CSP/CORS của trang FortiGate) nên gửi
 * message vào đây; background có host_permissions → fetch không bị chặn.
 * ─────────────────────────────────────────────────────────────────────────── */
chrome.runtime.onMessage.addListener(function (msg, sender, reply) {
  if (msg && msg.type === "poll") {
    fetch("http://127.0.0.1:8080/next", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) { reply(d || {}); })
      .catch(function () { reply({}); });
    return true; // giữ kênh mở cho reply bất đồng bộ
  }
});
