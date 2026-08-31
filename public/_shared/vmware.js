/* ═══════════════════════════════════════════════════════════════════════════
   _shared/vmware.js — LOGIC CHUNG cho MỌI trang VMware ESXi
   ───────────────────────────────────────────────────────────────────────────
   ⚠️ ĐỂ Ở public/_shared/ (gốc), CỐ Ý KHÔNG để trong service-home/ hay
   service-movi/. Lý do: anh Thoại muốn hai mảng Home và Movi TÁCH BẠCH, có thể
   xoá hẳn service-movi/ sau này mà Home vẫn chạy. Đặt file này bên trong một
   trong hai mảng là tạo ràng buộc chéo — xoá mảng kia là mảng này gãy.

   Dùng bởi: service-home/vmware-home.html · service-movi/vmware01-movi.html
             · service-movi/vmware02-movi.html

   ───────────────────────────────────────────────────────────────────────────
   HỢP ĐỒNG — trang HTML phải khai TRƯỚC khi nạp file này:

     var API_BASE = '/api/vmware-home';   // endpoint API của host
     var PERM_KEY = 'esxi';               // KHOÁ QUYỀN trong __USER__.permissions

   ⚠️ PERM_KEY là KHOÁ QUYỀN, KHÔNG phải tên file. Từng dính lỗi thật: trang Home
   dùng nhầm 'vmware-home' (tên file) thay vì 'esxi' (khoá quyền thật, khai ở
   src/permissions-registry.js) → permissions['vmware-home'] luôn undefined → mọi
   người rơi về 'read', ai được cấp quyền GHI vẫn chỉ xem được. Admin không lộ ra
   vì có nhánh isAdmin chặn trước. Sửa 2026-08-15.

   ───────────────────────────────────────────────────────────────────────────
   KHÔNG chứa phần theme/đồng hồ/thanh điều hướng — đó là "khung trang", do
   _shared/common.js lo. Bản cũ (service-movi/_shared/vmware-movi.js) có nhét
   sẵn một đoạn tự gắn theme+clock; nếu để nguyên thì trang Home nạp vào sẽ có
   HAI trình xử lý cùng bấm một nút → bấm đổi giao diện hai lần → nhìn như không
   ăn gì. Đã cắt bỏ khi gom về đây (2026-08-20).
   Riêng dòng hiện link Settings cho admin thì GIỮ, vì nó có kiểm null nên trang
   nào không có phần tử đó cũng vô hại.
   ═══════════════════════════════════════════════════════════════════════════ */
function _readUserCookie() {
  try { var m = document.cookie.match(/(?:^|;\s*)dh_user=([^;]+)/); return m ? JSON.parse(decodeURIComponent(m[1])) : null; } catch(e) { return null; }
}
var __USER__ = window.__USER__ || _readUserCookie() || { role:'user', permissions:{}, isAdmin:false };
var __PERM__  = __USER__.isAdmin ? 'write' : (__USER__.permissions[PERM_KEY] || 'read');
var allVMs = [], hostData = null, datastores = [];

function fmtUptime(secs) {
  if (!secs) return '—';
  var d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}
function fmtMem(mb) {
  if (!mb && mb !== 0) return '—';
  return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : mb + ' MB';
}
function fmtGB(gb) { return (!gb && gb !== 0) ? '—' : gb.toFixed(1) + ' GB'; }
function barColor(pct) { return pct >= 90 ? 'fill-red' : pct >= 70 ? 'fill-amber' : 'fill-green'; }
/* [security] escape HTML — chặn XSS từ tên VM/datastore/annotation (dữ liệu từ ESXi) */
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function hostStatusColor(s) { return s === 'green' ? 'c-green' : s === 'yellow' ? 'c-amber' : s === 'red' ? 'c-red' : ''; }
function timeAgo(iso) {
  if (!iso) return '—';
  var diff = Date.now() - new Date(iso).getTime();
  var m = Math.floor(diff / 60000);
  if (m < 1) return 'vừa xong';
  if (m < 60) return m + 'ph';
  var h = Math.floor(m / 60);
  if (h < 24) return h + 'h ' + (m % 60) + 'm';
  return Math.floor(h / 24) + 'd';
}

function row(key, val) {
  return '<div class="info-row"><span class="info-key">' + key + '</span><span class="info-val">' + val + '</span></div>';
}

function renderHost() {
  var h = hostData;
  if (!h) { document.getElementById('hostInfo').innerHTML = '<div class="empty">Không có dữ liệu host</div>'; return; }
  var statusLabel = h.overallStatus === 'green' ? '✓ Normal' : h.overallStatus === 'yellow' ? '⚠ Warning' : h.overallStatus || '—';
  var statusCls   = hostStatusColor(h.overallStatus);
  document.getElementById('hostInfo').innerHTML = [
    row('Hostname',     h.name || '—'),
    row('CPU Model',    h.cpuModel || '—'),
    row('CPU Cores',    h.numCpuCores + ' cores / ' + h.numCpuThreads + ' threads'),
    row('Total Memory', fmtMem(h.memTotalMB)),
    row('Uptime',       fmtUptime(h.uptime)),
    row('Connection',   h.connectionState || '—'),
    row('Status',       '<span class="' + statusCls + '">' + statusLabel + '</span>'),
  ].join('');
  var cpuBar = barColor(h.cpuPct), memBar = barColor(h.memPct);
  document.getElementById('hostRes').innerHTML =
    '<div class="res-block">'
    + '<div class="res-header"><span class="res-label">CPU</span>'
    + '<span class="res-nums">' + h.usedCpuMhz + ' / ' + h.totalCpuMhz + ' MHz (' + h.cpuPct + '%)</span></div>'
    + '<div class="res-bar"><div class="res-fill ' + cpuBar + '" style="width:' + h.cpuPct + '%"></div></div>'
    + '</div>'
    + '<div class="res-block">'
    + '<div class="res-header"><span class="res-label">Memory</span>'
    + '<span class="res-nums">' + fmtMem(h.memUsedMB) + ' / ' + fmtMem(h.memTotalMB) + ' (' + h.memPct + '%)</span></div>'
    + '<div class="res-bar"><div class="res-fill fill-blue" style="width:' + h.memPct + '%"></div></div>'
    + '</div>';
  document.getElementById('st-cpu').textContent = h.cpuPct + '%';
  document.getElementById('st-mem').textContent = h.memPct + '%';
}

function renderDatastores() {
  document.getElementById('dsCount').textContent = datastores.length;
  if (!datastores.length) { document.getElementById('dsList').innerHTML = '<div class="empty">Không có datastore</div>'; return; }
  document.getElementById('dsList').innerHTML = datastores.map(function(ds) {
    var pctBar = barColor(ds.usedPct);
    return '<div class="ds-item">'
      + '<div class="ds-header"><div class="ds-name">' + esc(ds.name || '—') + '</div>'
        + '<span style="font-size:11px;color:var(--muted)">' + ds.usedPct + '% used</span></div>'
      + '<div class="ds-meta"><span class="ds-type">' + (ds.type || 'Unknown') + '</span>'
        + '<span>' + fmtGB(ds.usedGB) + ' used of ' + fmtGB(ds.capacityGB) + '</span>'
        + '<span style="color:var(--green)">Free: ' + fmtGB(ds.freeGB) + '</span></div>'
      + '<div class="res-bar"><div class="res-fill ' + pctBar + '" style="width:' + ds.usedPct + '%"></div></div>'
    + '</div>';
  }).join('');
}

function renderVMs() {
  var q = (document.getElementById('vmSearch').value || '').toLowerCase();
  var list = allVMs.filter(function(v) {
    return !q || (v.name||'').toLowerCase().includes(q)
      || (v.ipAddress||'').includes(q)
      || (v.guestOS||'').toLowerCase().includes(q)
      || (v.hostName||'').toLowerCase().includes(q);
  });
  document.getElementById('vmCount').textContent = list.length + '/' + allVMs.length;
  if (!list.length) {
    document.getElementById('vmTableBody').innerHTML = '<tr><td colspan="9"><div class="empty">Không tìm thấy VM</div></td></tr>';
    return;
  }
  document.getElementById('vmTableBody').innerHTML = list.map(function(v) {
    var ps = v.powerState;
    var badgeCls = ps === 'poweredOn' ? 'power-on' : ps === 'suspended' ? 'power-sus' : 'power-off';
    var badgeTxt = ps === 'poweredOn' ? '▶ Running' : ps === 'suspended' ? '⏸ Suspended' : '■ Stopped';
    var cpuBar = '<div style="font-size:11px;font-variant-numeric:tabular-nums">' + v.cpuUsageMhz + ' MHz</div>'
      + '<div class="mini-bar"><div class="mini-fill ' + barColor(v.cpuPct) + '" style="width:' + Math.min(v.cpuPct,100) + '%"></div></div>';
    var memBar = '<div style="font-size:11px">' + fmtMem(v.memUsedMB) + ' / ' + fmtMem(v.memoryMB) + '</div>'
      + '<div class="mini-bar"><div class="mini-fill fill-blue" style="width:' + Math.min(v.memPct,100) + '%"></div></div>';
    var uptimeTxt = ps === 'poweredOn' ? timeAgo(v.bootTime) : '—';
    var n = (v.name||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'&quot;');
    var actions = '';
    if (__PERM__ !== 'write') {
      actions = '<span style="font-size:11px;color:var(--muted)">👁 Read only</span>';
    } else if (ps === 'poweredOff' || ps === 'suspended') {
      actions += '<button class="btn-power" style="color:var(--green)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'powerOn\')">▶ Bật</button>';
    } else {
      actions += '<button class="btn-power" style="color:var(--accent)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'rebootGuest\')" title="Restart mềm">↺ Restart</button>';
      actions += '<button class="btn-power" style="color:var(--amber)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'suspend\')">⏸ Suspend</button>';
      actions += '<button class="btn-power" style="color:var(--muted)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'shutdownGuest\')" title="Shutdown mềm">🔽 Shutdown</button>';
      actions += '<button class="btn-power" style="color:var(--red)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'powerOff\')" title="Force off">⬛ Force Off</button>';
      actions += '<button class="btn-power" style="color:var(--purple)" onclick="doPower(\'' + v.id + '\',\'' + n + '\',\'reset\')" title="Hard reset">⚡ Hard Reset</button>';
    }
    return '<tr>'
      + '<td><div class="vm-name">' + esc(v.name||'—') + '</div>'
        + (v.annotation ? '<div class="vm-sub" title="' + esc(v.annotation) + '">' + esc(v.annotation) + '</div>' : '')
      + '</td>'
      + '<td><span class="power-badge ' + badgeCls + '">' + badgeTxt + '</span></td>'
      + '<td><div class="power-actions">' + actions + '</div></td>'
      + '<td><div style="font-size:11px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(v.guestOS||'—') + '</div></td>'
      + '<td>' + (v.numCPU ? v.numCPU + ' vCPU' : '—') + (ps === 'poweredOn' ? '<br>' + cpuBar : '') + '</td>'
      + '<td>' + (ps === 'poweredOn' ? memBar : fmtMem(v.memoryMB)) + '</td>'
      + '<td>' + fmtGB(v.storageGB) + '</td>'
      + '<td>' + (v.ipAddress ? '<span class="ip-badge">' + v.ipAddress + '</span>' : '<span style="color:var(--muted)">—</span>') + '</td>'
      + '<td style="color:var(--muted);font-size:11px">' + uptimeTxt + '</td>'
    + '</tr>';
  }).join('');
}

function doPower(vmId, vmName, action) {
  var actionTexts = {
    'powerOn':'Bật','powerOff':'Force Off (tắt ngay)','suspend':'Suspend',
    'reset':'Hard Reset','shutdownGuest':'Shutdown (tắt mềm)','rebootGuest':'Restart (khởi động lại)',
  };
  if (!confirm('Bạn có chắc muốn ' + actionTexts[action] + ' VM "' + vmName + '"?')) return;
  var btns = document.querySelectorAll('.btn-power');
  btns.forEach(function(b){ b.disabled = true; });
  fetch(API_BASE + '/power', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ vmId: vmId, action: action })
  })
  .then(function(r){ return r.json(); })
  .then(function(res){
    if (res.error || !res.success) alert('Lỗi: ' + (res.error || 'Unknown error'));
    else setTimeout(loadData, 1000);
  })
  .catch(function(e){ alert('Lỗi gửi request: ' + e.message); })
  .finally(function(){ btns.forEach(function(b){ b.disabled = false; }); });
}

function loadData() {
  document.getElementById('statusDot').style.background = 'var(--amber)';
  document.getElementById('statusDot').style.boxShadow  = '0 0 6px var(--amber)';
  fetch(API_BASE, { cache: 'no-store' })
    .then(function(r){ return r.json(); })
    .then(function(data){
      if (data.about && data.about.fullName)
        document.getElementById('esxiVersion').textContent = data.about.fullName;
      var s = data.stats || {};
      document.getElementById('st-total').textContent = s.totalVMs  ?? '—';
      document.getElementById('st-on').textContent    = s.poweredOn  ?? '—';
      document.getElementById('st-off').textContent   = s.poweredOff ?? '—';
      document.getElementById('st-sus').textContent   = s.suspended  ?? '—';
      if (data.error && !data.host) {
        document.getElementById('hostInfo').innerHTML =
          '<div class="err-banner">⚠ ' + esc(data.error) + '</div>';
        document.getElementById('statusDot').style.background = 'var(--amber)';
        document.getElementById('statusDot').style.boxShadow  = '0 0 6px var(--amber)';
        return;
      }
      hostData   = data.host || null;
      allVMs     = data.vms || [];
      datastores = data.datastores || [];
      renderHost();
      renderVMs();
      renderDatastores();
      var ok = hostData && hostData.connectionState === 'connected';
      document.getElementById('statusDot').style.background = ok ? 'var(--green)' : 'var(--red)';
      document.getElementById('statusDot').style.boxShadow  = ok ? '0 0 6px var(--green)' : '0 0 6px var(--red)';
      var now = new Date();
      document.getElementById('lastUpdate').textContent =
        now.getHours().toString().padStart(2,'0') + ':' + now.getMinutes().toString().padStart(2,'0');
    })
    .catch(function(e){
      document.getElementById('hostInfo').innerHTML = '<div class="err-banner">⚠ ' + esc(e.message) + '</div>';
      document.getElementById('statusDot').style.background = 'var(--red)';
      document.getElementById('statusDot').style.boxShadow  = '0 0 6px var(--red)';
    });
}

loadData();
/* [2026-08-28] Ẩn tab thì bỏ nhịp này, không gọi máy chủ. Bọc một lớp mỏng thay
   vì sửa loadData() — hàm đó đang chạy tốt, không đụng vào. Lần tải đầu ở trên
   vẫn chạy như cũ. Cùng cách với dinhKy() trong fortigate-movi.html. */
setInterval(function(){ if (!document.hidden) loadData(); }, 300000);

/* Hiện link Settings nếu người dùng là admin.
   Có kiểm null nên trang không có phần tử #settings-link thì bỏ qua, vô hại. */
(function(){
  var sl = document.getElementById('settings-link');
  if (sl && (__USER__.isAdmin || __USER__.role === 'admin')) sl.style.display = '';
})();
