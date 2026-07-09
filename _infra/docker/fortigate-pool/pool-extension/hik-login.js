/* ── Hikvision DVR (192.168.130.3:8088) auto-login — CHẠY TRONG MAIN WORLD ──
 * Khai báo trong manifest với "world":"MAIN" → Chrome bơm script này thẳng vào
 * page world (KHÔNG phải inline <script> nên KHÔNG dính CSP của trang) và có
 * window.angular thật. Trang login Hikvision dùng AngularJS + ô password mã hoá
 * client-side, nên PHẢI set ngModel qua $setViewValue (set .value thường không
 * cập nhật model → login() đọc rỗng). Creds lấy từ hik-creds.js (cùng entry).
 * Chỉ match đúng host DVR (manifest) nên không lộ ra site khác.
 */
(function () {
  var U = (typeof HIK_USER !== "undefined" && HIK_USER) ? HIK_USER : "admin";
  var P = (typeof HIK_PASS !== "undefined") ? HIK_PASS : "";
  if (!P) return;

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
  // Set qua ngModel ($setViewValue) — đúng cách AngularJS; có fallback .value.
  function ngSet(el, v){
    if(!el) return;
    var ng=window.angular;
    if(ng){ try{ var c=ng.element(el).controller('ngModel'); if(c){ c.$setViewValue(v); c.$render(); } }catch(e){} }
    try{ var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value'); if(d&&d.set) d.set.call(el,v); else el.value=v; }catch(e){ el.value=v; }
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
  }
  function digest(el){ var ng=window.angular; if(!ng) return; try{ var s=ng.element(el).scope(); if(s){ var r=s.$root||s; if(!r.$$phase) s.$apply(); } }catch(e){} }
  function clickFull(el){
    if(!el) return;
    try{ el.scrollIntoView({block:'center'}); }catch(e){}
    var o={bubbles:true,cancelable:true,view:window};
    var ev=['mousedown','mouseup','click'];
    for(var i=0;i<ev.length;i++){ try{ el.dispatchEvent(new MouseEvent(ev[i],o)); }catch(e){} }
    try{ el.click(); }catch(e){}
  }

  var tries=0, done=0;
  var timer=setInterval(function(){
    tries++;
    var pw=passField(), un=userField();
    if(!pw||!un){ if(tries>80) clearInterval(timer); return; }
    if(un.value!==U || pw.value!==P){ ngSet(un, U); ngSet(pw, P); digest(pw); }

    if(pw.value===P && done<2){
      done++;
      var n=done;
      try{ un.dispatchEvent(new Event('blur',{bubbles:true})); pw.dispatchEvent(new Event('blur',{bubbles:true})); }catch(e){}
      digest(pw);
      setTimeout(function(){
        if(!passField()){ clearInterval(timer); return; } // đã rời trang login → xong
        var ng=window.angular, btn=findBtn();
        if(n===1){
          if(btn) clickFull(btn);                 // click THẬT → ng-click="login()" chạy đúng context, model đã đúng
        } else {
          var ok=false;                            // lần 2: gọi thẳng scope.login()
          if(ng && btn){ try{ var s=ng.element(btn).scope(); if(s && typeof s.login==='function'){ s.login(); var r=s.$root||s; if(!r.$$phase) s.$apply(); ok=true; } }catch(e){} }
          if(!ok && btn) clickFull(btn);
          clearInterval(timer);
        }
      }, n===1 ? 500 : 2800);
    } else if(tries>80){ clearInterval(timer); }
  }, 500);
})();
