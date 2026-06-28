/* ───────────────────────────────────────────────────────────────────────────
 * sw.js — relay fetch + chủ động poll navigator để navigate tab.
 *
 * Trước: chỉ relay cho content script → content script chết khi Chrome kẹt
 * ở trang lỗi (ERR_CONNECTION_REFUSED) → lệnh navigate bị bỏ qua.
 *
 * Sau: SW tự poll + dùng chrome.tabs.update() → hoạt động kể cả khi
 * Chrome đang ở trang lỗi, about:blank, hay bất kỳ trang nào.
 * ─────────────────────────────────────────────────────────────────────────── */

function pollAndNavigate() {
  fetch("http://127.0.0.1:8080/next", { cache: "no-store" })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d || !d.url) return;
      chrome.tabs.query({}, function(tabs) {
        if (!tabs || !tabs.length) return;
        var tab = tabs[0];
        if (tab.url !== d.url) {
          chrome.tabs.update(tab.id, { url: d.url });
        }
      });
    })
    .catch(function() {});
}

// Polling nhanh khi SW đang hoạt động (content script messages giữ SW thức)
setInterval(pollAndNavigate, 1500);

// Alarm đánh thức SW khi bị sleep (Chrome throttle minimum ~1 phút)
chrome.alarms.create('nav-poll', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(function(alarm) {
  if (alarm.name === 'nav-poll') pollAndNavigate();
});

// Relay cho content script (backward compat)
chrome.runtime.onMessage.addListener(function (msg, sender, reply) {
  if (msg && msg.type === "poll") {
    fetch("http://127.0.0.1:8080/next", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) { reply(d || {}); })
      .catch(function () { reply({}); });
    return true;
  }
});
