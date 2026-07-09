/* ───────────────────────────────────────────────────────────────────────────
 * sw.js — điều hướng tab theo lệnh từ navigator (long-poll).
 *
 * Trước: setInterval(1500) trong service worker MV3 → SW ngủ sau ~30s, chỉ được
 * đánh thức bằng alarm tối thiểu ~1 phút. Khi Chrome kẹt ở trang lỗi
 * (chrome-error://) content script cũng chết → lệnh navigate không ai nhận →
 * KẸT, phải restart docker.
 *
 * Sau (2026-07-01): LONG-POLL. Mỗi fetch /next chờ tới ~25s; fetch-đang-chờ giữ
 * SW luôn "thức". Có lệnh → navigate TỨC THÌ bằng chrome.tabs.update() (chạy
 * được kể cả khi tab đang ở trang lỗi). Alarm 1' là lưới an toàn: nếu SW bị
 * Chrome kill (giới hạn ~5') thì alarm đánh thức → chạy lại vòng long-poll.
 * ─────────────────────────────────────────────────────────────────────────── */

const NAV_NEXT = "http://127.0.0.1:8080/next";
let _looping = false;

async function navigateTo(url) {
  try {
    // Ưu tiên tab active của cửa sổ vừa focus; fallback tab đầu tiên.
    let tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tabs || !tabs.length) tabs = await chrome.tabs.query({ active: true });
    if (!tabs || !tabs.length) tabs = await chrome.tabs.query({});
    const tab = tabs && tabs[0];
    if (tab && tab.url !== url) await chrome.tabs.update(tab.id, { url });
  } catch (e) { /* ignore */ }
}

async function longPollLoop() {
  if (_looping) return;          // tránh chạy 2 vòng song song trong cùng 1 SW
  _looping = true;
  try {
    for (;;) {
      try {
        const r = await fetch(NAV_NEXT, { cache: "no-store" });
        const d = await r.json();
        if (d && d.url) await navigateTo(d.url);
        // Có url hay không (timeout) đều vòng lại NGAY → giữ fetch liên tục.
      } catch (e) {
        // navigator chưa sẵn sàng / lỗi mạng → nghỉ ngắn rồi thử lại.
        await new Promise(res => setTimeout(res, 1000));
      }
    }
  } finally {
    _looping = false;
  }
}

// Chạy ngay khi SW khởi động (kể cả khi được alarm đánh thức lại).
longPollLoop();

// Lưới an toàn: nếu SW bị kill, alarm đánh thức → chạy lại longPollLoop().
chrome.alarms.create("nav-poll", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === "nav-poll") longPollLoop();
});

// Relay cho content script (poller.js) — đường nhanh khi ở trang bình thường.
chrome.runtime.onMessage.addListener(function (msg, sender, reply) {
  if (msg && msg.type === "poll") {
    fetch(NAV_NEXT, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (d) { reply(d || {}); })
      .catch(function () { reply({}); });
    return true;
  }
});
