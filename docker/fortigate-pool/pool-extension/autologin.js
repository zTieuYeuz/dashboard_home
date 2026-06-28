/* ───────────────────────────────────────────────────────────────────────────
 * FortiGate Auto-Login (content script). User/pass lấy từ creds.js (tự sinh
 * lúc khởi động từ biến môi trường FGT_USER / FGT_PASS).
 * LƯU Ý: tài khoản auto-login KHÔNG được bật 2FA/FortiToken.
 * ─────────────────────────────────────────────────────────────────────────── */
/* ── Hikvision DVR (192.168.130.3:8088) auto-login ──
 * Trang login do JS render nên không biết trước selector chính xác → dùng
 * heuristic: tìm ô password, ô username (text input đứng trước/visible), nút
 * đăng nhập. User/pass lấy từ HIK_USER / HIK_PASS (sinh trong creds.js).
 * Chỉ chạy khi host khớp DVR → không đụng các trang khác.
 */
(function () {
  var HOSTS = ["192.168.130.3"];
  if (HOSTS.indexOf(location.hostname) === -1) return;

  var U = (typeof HIK_USER !== "undefined" && HIK_USER) ? HIK_USER : "admin";
  var P = (typeof HIK_PASS !== "undefined") ? HIK_PASS : "";
  if (!P) return;

  function visible(el) {
    if (!el) return false;
    var r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && el.offsetParent !== null;
  }
  function setVal(el, v) {
    el.focus();
    el.value = v;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  }
  function findLoginBtn(scope) {
    var sel = ['#login', '#loginBtn', '#login-btn', '.login-btn',
               'button[type=submit]', 'input[type=submit]'];
    for (var i = 0; i < sel.length; i++) {
      var b = (scope || document).querySelector(sel[i]);
      if (b && visible(b)) return b;
    }
    // fallback: nút/anchor có text Login / Đăng nhập / 登录
    var cands = (scope || document).querySelectorAll("button, a, input[type=button], div[role=button]");
    for (var j = 0; j < cands.length; j++) {
      var t = (cands[j].textContent || cands[j].value || "").trim().toLowerCase();
      if (visible(cands[j]) && /login|log in|đăng nhập|sign in|登录/.test(t)) return cands[j];
    }
    return null;
  }

  var done = false, tries = 0;
  var timer = setInterval(function () {
    tries++;

    // Ưu tiên ID chuẩn của Hikvision (template ©2020: #username/#password/#login).
    var un = document.querySelector('#username');
    var pw = document.querySelector('#password');

    // Fallback heuristic nếu firmware khác đổi ID.
    if (!pw || !visible(pw)) {
      pw = null; var pws = document.querySelectorAll('input[type=password]');
      for (var i = 0; i < pws.length; i++) { if (visible(pws[i])) { pw = pws[i]; break; } }
    }
    if (!pw) { if (tries > 80) clearInterval(timer); return; }
    if (!un || !visible(un)) {
      un = null; var ins = document.querySelectorAll('input');
      for (var k = 0; k < ins.length; k++) {
        var ty = (ins[k].getAttribute("type") || "text").toLowerCase();
        if (ty !== "password" && ty !== "hidden" && ty !== "checkbox" &&
            ty !== "radio" && ty !== "submit" && ty !== "button" && visible(ins[k])) {
          un = ins[k]; break;
        }
      }
    }

    if (un && un.value !== U) setVal(un, U);
    if (pw.value !== P) setVal(pw, P);

    if (!done && un && un.value === U && pw.value === P) {
      done = true;
      clearInterval(timer);
      var b = document.querySelector('#login');
      if (!b || !visible(b)) b = findLoginBtn();
      setTimeout(function () {
        if (b) b.click();
        else pw.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Enter", keyCode: 13 }));
      }, 300);
    } else if (tries > 80) {
      clearInterval(timer);
    }
  }, 500);
})();

/* ── FortiGate auto-login (content script). User/pass lấy từ creds.js (tự sinh
 * lúc khởi động từ biến môi trường FGT_USER / FGT_PASS).
 * LƯU Ý: tài khoản auto-login KHÔNG được bật 2FA/FortiToken. ── */
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
