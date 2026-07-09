/* ───────────────────────────────────────────────────────────────────────────
 * poller.js (content script) — đường NHANH khi ở trang bình thường: hỏi navigator
 * (qua background sw.js, tránh CSP/CORS của trang) "có lệnh đổi site không?".
 * Có url mới → đổi trang bằng location.href (extension auto-login lo đăng nhập).
 *
 * 2026-07-01: self-schedule (1 request tại một thời điểm) thay cho setInterval —
 * vì sw.js /next giờ long-poll (chờ tới ~25s), setInterval sẽ chồng hàng chục
 * kết nối. Chỉ gửi request kế tiếp SAU khi request trước trả về.
 * (sw.js đã tự long-poll độc lập → đây chỉ là đường phụ, hỏng cũng không kẹt.)
 * ─────────────────────────────────────────────────────────────────────────── */
(function () {
  function poll() {
    try {
      chrome.runtime.sendMessage({ type: "poll" }, function (d) {
        if (!chrome.runtime.lastError && d && d.url && d.url !== location.href) {
          location.href = d.url;
          return;                       // đang rời trang → khỏi lặp tiếp
        }
        setTimeout(poll, 500);          // hỏi lại sau khi request trước xong
      });
    } catch (e) {
      setTimeout(poll, 1500);           // SW đang ngủ → thử lại sau
    }
  }
  poll();
})();
