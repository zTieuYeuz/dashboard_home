/* ───────────────────────────────────────────────────────────────────────────
 * FortiGate Auto-Login (content script)
 *
 * KHÔNG sửa file này nữa. User/pass lấy từ creds.js (tự sinh lúc khởi động từ
 * biến môi trường FGT_USER / FGT_PASS — khai trong .env của docker-compose).
 *
 * LƯU Ý 2FA: nếu tài khoản bật FortiToken/2FA thì auto-login KHÔNG hoàn tất
 * được (còn bước nhập mã token). Dùng tài khoản KHÔNG bật 2FA cho auto-login.
 *
 * Selector FortiOS đã xác nhận: #username, #secretkey, #login_button, #token_code
 * ─────────────────────────────────────────────────────────────────────────── */
(function () {
  // creds.js định nghĩa FGT_USER/FGT_PASS (cùng isolated world). Phòng khi thiếu.
  var U = (typeof FGT_USER !== "undefined") ? FGT_USER : "";
  var P = (typeof FGT_PASS !== "undefined") ? FGT_PASS : "";

  // Chưa cấu hình biến (creds rỗng) → không làm gì.
  if (!U) return;

  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    var u = document.querySelector("#username");
    var p = document.querySelector("#secretkey");
    var b = document.querySelector("#login_button");

    if (u && p && b) {
      clearInterval(timer);
      u.value = U; u.dispatchEvent(new Event("input", { bubbles: true }));
      p.value = P; p.dispatchEvent(new Event("input", { bubbles: true }));
      // chờ 1 nhịp cho FortiOS gắn handler rồi mới bấm Login
      setTimeout(function () { b.click(); }, 250);
    } else if (tries > 60) {
      clearInterval(timer); // ~30s không thấy form (đã đăng nhập rồi / trang khác) → thôi
    }
  }, 500);
})();
