/* ───────────────────────────────────────────────────────────────────────────
 * FortiGate Auto-Login (content script). User/pass lấy từ creds.js (tự sinh
 * lúc khởi động từ biến môi trường FGT_USER / FGT_PASS).
 * LƯU Ý: tài khoản auto-login KHÔNG được bật 2FA/FortiToken.
 * ─────────────────────────────────────────────────────────────────────────── */
(function () {
  var U = (typeof FGT_USER !== "undefined") ? FGT_USER : "";
  var P = (typeof FGT_PASS !== "undefined") ? FGT_PASS : "";
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
      setTimeout(function () { b.click(); }, 250);
    } else if (tries > 60) {
      clearInterval(timer);
    }
  }, 500);
})();
