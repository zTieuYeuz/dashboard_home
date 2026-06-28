/* ───────────────────────────────────────────────────────────────────────────
 * FortiGate Auto-Login (content script). User/pass lấy từ creds.js (tự sinh
 * lúc khởi động từ biến môi trường FGT_USER / FGT_PASS).
 * LƯU Ý: tài khoản auto-login KHÔNG được bật 2FA/FortiToken.
 * ─────────────────────────────────────────────────────────────────────────── */
/* ── Hikvision DVR (192.168.130.3:8088) auto-login — trang login dùng AngularJS ──
 * Content script chạy ở ISOLATED world → KHÔNG truy cập được window.angular của
 * trang, nên set .value chỉ điền hiển thị mà model AngularJS rỗng → login() thất
 * bại. Giải pháp: BƠM 1 script chạy trong PAGE world để dùng angular thật: set
 * ng-model qua $setViewValue rồi gọi login()/bấm nút .login-btn (có fallback DOM).
 * User/pass lấy từ HIK_USER / HIK_PASS (creds.js). Chỉ chạy đúng host DVR.
 * DVR (Server: Webs) không gửi CSP nên inline script chạy được.
 */
(function () {
  var HOSTS = ["192.168.130.3"];
  if (HOSTS.indexOf(location.hostname) === -1) return;

  var U = (typeof HIK_USER !== "undefined" && HIK_USER) ? HIK_USER : "admin";
  var P = (typeof HIK_PASS !== "undefined") ? HIK_PASS : "";
  if (!P) return;

  // Chạy trong PAGE world (được stringify + bơm vào <script>).
  function pageLogin(U, P) {
    var tries = 0, submits = 0, launched = false;
    function vis(el){ if(!el) return false; var r=el.getBoundingClientRect(); return r.width>0 && r.height>0 && el.offsetParent!==null; }
    function passField(){ var p=document.querySelectorAll('input[type=password]'); for(var i=0;i<p.length;i++){ if(vis(p[i])) return p[i]; } return null; }
    function userField(){ var a=document.querySelectorAll('input'); for(var i=0;i<a.length;i++){ var t=(a[i].getAttribute('type')||'text').toLowerCase(); if(t!=='password'&&t!=='hidden'&&t!=='checkbox'&&t!=='radio'&&t!=='submit'&&t!=='button'&&vis(a[i])) return a[i]; } return null; }
    function findBtn(){
      var b=document.querySelector('.login-btn,#login,#loginBtn,button[type=submit],input[type=submit]');
      if(b&&vis(b)) return b;
      var c=document.querySelectorAll('button,a,input[type=button],div[role=button]');
      for(var i=0;i<c.length;i++){ var t=(c[i].textContent||c[i].value||'').toLowerCase(); if(vis(c[i])&&/login|đăng nhập|sign in|登录/.test(t)) return c[i]; }
      return null;
    }
    function setField(el, v){
      if(!el) return;
      var ng=window.angular;
      if(ng){ try{ var c=ng.element(el).controller('ngModel'); if(c){ c.$setViewValue(v); c.$render(); } }catch(e){} }
      // luôn set value + bắn input/change để mọi directive (kể cả ô mã hoá) cập nhật
      try{ var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value'); if(d&&d.set) d.set.call(el,v); else el.value=v; }catch(e){ el.value=v; }
      el.dispatchEvent(new Event('input',{bubbles:true}));
      el.dispatchEvent(new Event('change',{bubbles:true}));
    }
    function digest(el){ var ng=window.angular; if(!ng) return; try{ var s=ng.element(el).scope(); if(s){ var r=s.$root||s; if(!r.$$phase) s.$apply(); } }catch(e){} }
    function clickFull(el){ if(!el) return; try{ el.scrollIntoView({block:'center'}); }catch(e){} var o={bubbles:true,cancelable:true,view:window}; var ev=['mousedown','mouseup','click']; for(var i=0;i<ev.length;i++){ try{ el.dispatchEvent(new MouseEvent(ev[i],o)); }catch(e){} } try{ el.click(); }catch(e){} }
    function submit(un, pw){
      submits++;
      var attempt = submits;
      setField(un, U); setField(pw, P);
      try{ un && un.dispatchEvent(new Event('blur',{bubbles:true})); }catch(e){}  // blur → form validate → bật nút
      try{ pw.dispatchEvent(new Event('blur',{bubbles:true})); }catch(e){}
      digest(pw);
      setTimeout(function(){
        var btn=findBtn();
        if(attempt === 1){
          if(btn) clickFull(btn);                         // cách 1: click THẬT → ng-click="login()" chạy đúng context
        } else {
          var ng=window.angular, done=false;              // cách 2 (lần thử 2): gọi scope.login() trực tiếp
          if(ng && btn){ try{ var s=ng.element(btn).scope(); if(s && typeof s.login==='function'){ s.login(); var r=s.$root||s; if(!r.$$phase) s.$apply(); done=true; } }catch(e){} }
          if(!done && btn) clickFull(btn);
        }
      }, 250);
      // Thử lại tối đa 2 lần, chỉ khi form CÒN (tránh Hikvision khoá tài khoản).
      if(submits<2){ setTimeout(function(){ if(passField()) submit(un, pw); }, 2800); }
    }
    var timer=setInterval(function(){
      tries++;
      var pw=passField();
      if(!pw){ if(tries>80) clearInterval(timer); return; }
      var un=userField();
      setField(un, U); setField(pw, P); digest(pw);
      if(!launched && pw.value===P){ launched=true; clearInterval(timer); setTimeout(function(){ submit(un, pw); }, 350); }
      else if(tries>80){ clearInterval(timer); }
    }, 500);
  }

  function inject(){
    try{
      var s=document.createElement('script');
      s.textContent='('+pageLogin.toString()+')('+JSON.stringify(U)+','+JSON.stringify(P)+');';
      (document.documentElement||document.head||document.body).appendChild(s);
      if(s.parentNode) s.parentNode.removeChild(s);
    }catch(e){}
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
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
