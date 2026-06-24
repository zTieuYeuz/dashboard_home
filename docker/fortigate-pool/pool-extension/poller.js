/* ───────────────────────────────────────────────────────────────────────────
 * poller.js (content script) — mỗi 1.5s hỏi navigator "có lệnh đổi site không?"
 * Fetch đi qua background (sw.js) để KHÔNG vướng CSP/CORS của trang FortiGate.
 * Có url mới → đổi trang bằng location.href (extension auto-login lo đăng nhập).
 * ─────────────────────────────────────────────────────────────────────────── */
(function () {
  setInterval(function () {
    try {
      chrome.runtime.sendMessage({ type: "poll" }, function (d) {
        if (chrome.runtime.lastError) return;
        if (d && d.url && d.url !== location.href) {
          location.href = d.url;
        }
      });
    } catch (e) { /* SW đang ngủ — bỏ qua, vòng sau thử lại */ }
  }, 1500);
})();
