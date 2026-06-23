/* ───────────────────────────────────────────────────────────────────────────
 * FortiGate Auto-Login (content script)
 *
 * >>> CHỈ SỬA 2 DÒNG creds bên dưới <<<
 * Điền username/password admin FortiGate vào đây. File này nằm TRONG container,
 * chỉ chạm tới được sau khi đã qua dashboard + Cloudflare Access (Gmail). Dù vậy
 * đây là mật khẩu dạng plaintext → nên dùng 1 tài khoản FortiGate riêng cho việc
 * này (đừng dùng super-admin nếu tránh được).
 *
 * LƯU Ý 2FA: nếu tài khoản này bật FortiToken/2FA thì auto-login KHÔNG hoàn tất
 * được (còn bước nhập mã token). Dùng tài khoản KHÔNG bật 2FA cho auto-login.
 * ─────────────────────────────────────────────────────────────────────────── */
var FGT_USER = "___DIEN_USERNAME___";
var FGT_PASS = "___DIEN_PASSWORD___";
/* ─────────────────────────────────────────────────────────────────────────── */

(function () {
  // Chưa điền creds (còn placeholder) → không làm gì.
  if (!FGT_USER || FGT_USER.indexOf("___") === 0) return;

  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    var u = document.querySelector("#username");
    var p = document.querySelector("#secretkey");
    var b = document.querySelector("#login_button");

    if (u && p && b) {
      clearInterval(timer);
      u.value = FGT_USER; u.dispatchEvent(new Event("input", { bubbles: true }));
      p.value = FGT_PASS; p.dispatchEvent(new Event("input", { bubbles: true }));
      // chờ 1 nhịp cho FortiOS gắn handler rồi mới bấm Login
      setTimeout(function () { b.click(); }, 250);
    } else if (tries > 60) {
      clearInterval(timer); // ~30s không thấy form (đã đăng nhập rồi / trang khác) → thôi
    }
  }, 500);
})();
