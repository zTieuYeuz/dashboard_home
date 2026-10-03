/* ═══════════════════════════════════════════════════════════
   USER / THEME SETUP
   ═══════════════════════════════════════════════════════════ */
function _readUserCookie() {
  try { var m=document.cookie.match(/(?:^|;\s*)dh_user=([^;]+)/); return m?JSON.parse(decodeURIComponent(m[1])):null; } catch(e){return null;}
}
var __USER__ = window.__USER__ || _readUserCookie() || { username:'?', role:'user', isAdmin:false };

/* ═══════════════════════════════════════════════════════════════════════
   NGUỒN QUYỀN: src/permissions-registry.js (server bơm vào __PERM_REGISTRY__).
   Thêm service mới → khai báo Ở ĐÓ, KHÔNG sửa các danh sách trong file này.
   Các biến dưới đây chỉ là bản dựng lại từ registry; nhánh fallback giữ nguyên
   danh sách cũ để trang vẫn chạy nếu vì lý do nào đó registry chưa được bơm.
   ═══════════════════════════════════════════════════════════════════════ */
var _REG = (window.__PERM_REGISTRY__ || null);

/* Human-readable names for all service IDs — must be declared BEFORE initUI() runs */
var DELEGATE_SVC_LABELS = _REG ? _REG.labels : {
  /* ── Service Home ── */
  'esxi':'VMware ESXi','n8n':'n8n Automation','casaos':'CasaOS',
  'fortigate':'FortiGate','asus':'ASUS Router',
  'ssh':'SSH Terminal','console-serial':'Web Console (Serial)','camera':'Camera Home · Live','camera_playback':'Camera Home · Playback','camera_download':'Camera Home · Tải video','app_camera':'Camera Home · Mở thẳng camera khi login','camera_autoopen':'Camera Home · Tự động mở tất cả camera','rustdesk':'RustDesk Remote',

  'services-hub':'Services Hub (Internal)',
  'hub-fortigate':'Hub · FortiGate','hub-asus':'Hub · Router Asus','hub-esxi':'Hub · VMware ESXi','hub-nas':'Hub · NAS','hub-casaos':'Hub · CasaOS','hub-kasm':'Hub · Kasm',
  'hub-openclaw':'Hub · OpenClaw','hub-n8n':'Hub · n8n','hub-frigate':'Hub · Frigate NVR','hub-camera-nvr':'Hub · Camera NVR','hub-pnetlab':'Hub · Pnetlab-network',
};
var _DELEGATE_HOME = _REG ? _REG.delegateHome : ['esxi','n8n','casaos','fortigate','asus','ssh','console-serial','camera','camera_playback','camera_download','app_camera','camera_autoopen','rustdesk','services-hub','hub-fortigate','hub-asus','hub-esxi','hub-nas','hub-casaos','hub-kasm','hub-openclaw','hub-n8n','hub-frigate','hub-camera-nvr','hub-pnetlab'];
var _delegateMode = false;   // true when current user is a delegated manager (not admin)
var _delegateServices = [];  // services the current delegated user can manage
function _normalizeDelegateSvcs(arr) {
  return (arr || []).slice();
}

(function initUI() {
  document.getElementById('user-avatar').textContent = (__USER__.username||'?').charAt(0).toUpperCase();
  document.getElementById('user-name').textContent = __USER__.username||'?';
  if (__USER__.isAdmin) {
    document.getElementById('user-tag').style.display='';
  } else {
    // Non-admin: hide admin-only tabs, switch to account tab as default
    document.querySelectorAll('.admin-only').forEach(function(el){ el.style.display='none'; });
    // Deactivate users tab, activate account tab
    document.getElementById('tc-users').classList.remove('active');
    document.getElementById('tc-account').classList.add('active');
    document.getElementById('tab-btn-account').classList.add('active');
    document.getElementById('tab-btn-users').classList.remove('active');
    // Update descriptions for regular users
    var sub = document.querySelector('.page-sub');
    if (sub) sub.textContent = 'Quản lý tài khoản cá nhân và xem lịch sử hoạt động';
    var auditDesc = document.getElementById('audit-panel-desc');
    if (auditDesc) auditDesc.textContent = 'Lịch sử hoạt động của tài khoản bạn (30 ngày)';

    // If this user has delegation rights → selectively show Users/UserGroups/Roles tabs
    var cmp = __USER__.canManagePerms || [];
    var sp = __USER__.sysPerms || {};
    if (cmp.length > 0 || sp.addUser || sp.resetMfa || sp.blockUser) {
      _delegateMode = true; _delegateServices = _normalizeDelegateSvcs(cmp);
      // Show Users tab (renamed)
      var tabU = document.getElementById('tab-btn-users');
      if (tabU) {
        tabU.style.display = '';
        tabU.textContent = cmp.length > 0 ? '🔑 Quản lý Quyền' : '👥 Quản lý User';
        tabU.classList.add('active');
        document.getElementById('tc-users').classList.add('active');
        document.getElementById('tc-account').classList.remove('active');
        document.getElementById('tab-btn-account').classList.remove('active');
      }
      // Show User Groups tab only for full delegates
      if (cmp.length > 0 || sp.addUser) {
        var tabUG = document.getElementById('tab-btn-usergroups');
        if (tabUG) { tabUG.style.display = ''; }
        // Show Role Management tab
        var tabR = document.getElementById('tab-btn-roles');
        if (tabR) { tabR.style.display = ''; }
      }
      // Show a delegate banner in the users panel
      var ph = document.querySelector('#tc-users .panel-header');
      if (ph) {
        var desc = ph.querySelector('.panel-desc');
        if (desc) {
          if (cmp.length > 0)
            desc.textContent = 'Bạn được ủy quyền quản lý cho: ' + cmp.map(function(s){return DELEGATE_SVC_LABELS[s]||s;}).join(', ');
          else if (sp.addUser)
            desc.textContent = 'Bạn được quyền tạo user mới trong hệ thống.';
          else {
            var acts = [];
            if (sp.resetMfa) acts.push('Reset MFA');
            if (sp.blockUser) acts.push('Chặn / Bỏ chặn User');
            desc.textContent = 'Quyền hệ thống: ' + acts.join(', ') + '.';
          }
        }
        // Hide "Add User" button if delegate does NOT have sysPerms.addUser
        if (!sp.addUser) {
          var addBtn = ph.querySelector('.btn-primary');
          if (addBtn) addBtn.style.display = 'none';
        }
      }
    }
    // sysPerms.systemConfig → show System Config tab
    if (sp.systemConfig) {
      var tabSC = document.getElementById('tab-btn-sysconfig');
      if (tabSC) { tabSC.style.display = ''; }
    }
  }
  // Theme
  var saved=null; try{saved=localStorage.getItem('dh_theme')}catch(e){}
  if(saved==='light') document.documentElement.dataset.theme='light';
  document.getElementById('themeToggle').addEventListener('click',function(){
    var next=document.documentElement.dataset.theme==='light'?'dark':'light';
    document.documentElement.dataset.theme=next;
    try{localStorage.setItem('dh_theme',next)}catch(e){}
  });
  setInterval(function(){var c=document.getElementById('clock');if(c)c.textContent=new Date().toLocaleTimeString('vi-VN',{hour12:false});},1000);
})();

function doLogout(){fetch('/api/auth/logout',{method:'POST'}).finally(function(){window.location.href='/login.html';})}

/* ═══════════════════════════════════════════════════════════
   TOAST
   ═══════════════════════════════════════════════════════════ */
var _toastT;
function toast(msg, cls) {
  var el=document.getElementById('toast');
  el.textContent=msg; el.className='show '+(cls||'info');
  clearTimeout(_toastT);
  _toastT=setTimeout(function(){el.className='';},3000);
}

/* ═══════════════════════════════════════════════════════════
   TAB SWITCHER
   ═══════════════════════════════════════════════════════════ */
function switchTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(function(el){el.classList.remove('active');});
  document.querySelectorAll('.main-tab').forEach(function(el){el.classList.remove('active');});
  document.getElementById('tc-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='sysconfig' && typeof loadSessions==='function') loadSessions();
  if(id==='ai' && typeof loadAi==='function') loadAi();
}

/* ═══════════════════════════════════════════════════════════
   MODAL HELPERS
   ═══════════════════════════════════════════════════════════ */
function openModal(id){document.getElementById(id).classList.remove('hidden');}
function closeModal(id){document.getElementById(id).classList.add('hidden');}

/* ═══════════════════════════════════════════════════════════
   PERMISSION STRUCTURE DEFINITIONS
   ─────────────────────────────────────────────────────────
   HOW TO ADD A NEW SERVICE:
   1. Khai báo trong src/permissions-registry.js (SERVICE_HOME_PAGES dựng từ đó).
   2. Fields:
      id        – matches the permission key in KV (e.g. 'my-service')
      name      – display name shown in the editor
      icon      – emoji icon
      perms     – allowed permission levels: ['none','read','write'] or ['none','write']
      permLabels– (optional) custom labels for the radio buttons
      panels    – (optional) array of sub-panels, each {id, name}
                  panel id MUST start with the page id: 'my-service.panel1'
      hasCameras– (optional) true if this service has camera selection
      camClass  – (required if hasCameras) unique CSS class for the checkboxes
   3. That's it — renderPermEditor & collectPermissions iterate these arrays dynamically.
   ═══════════════════════════════════════════════════════════ */
/* Chuyển 1 mục registry → dạng mà renderPermEditor/collectPermissions đang dùng.
   Nhờ vậy thêm service mới chỉ cần khai báo trong permissions-registry.js, KHÔNG
   phải sửa file này nữa. Các nhóm có giao diện riêng (Services Hub, Camera Home,
   tool-group) giữ nguyên `type` cũ để tái dùng đúng code render đã chạy ổn định. */
function _regToPage(svc) {
  if (svc.customUI === 'camera-home-group') return { type:'camera-home-group', id:'camera-home-group', icon:svc.icon, name:svc.name };
  if (svc.featureGroups)                    return { type:'services-hub-group', id:'services-hub-group', icon:svc.icon, name:svc.name };
  var perms = svc.access === 'rw' ? ['none','read','write']
            : svc.access === 'toggle-read' ? ['none','read']
            : ['none','write'];
  var page = { id:svc.id, name:svc.name, icon:svc.icon, perms:perms };
  if (svc.access !== 'rw') page.permLabels = svc.access === 'toggle-read'
    ? {'none':'Không truy cập','read':'Truy cập'}
    : {'none':'Không truy cập','write':'Truy cập'};
  if (svc.customUI === 'tool-group') {
    page.type = 'tool-group';
    page.tools = (svc.features||[]).map(function(f){ return {id:f.id, name:f.name, icon:f.icon}; });
    return page;
  }
  if (svc.panels) page.panels = svc.panels;
  /* ⚠️ BUG THẬT (phát hiện 2026-08-15 khi rà soát): `features` thường (KHÔNG kèm
     customUI) trước đây bị BỎ QUA hoàn toàn ở đây. Hậu quả: 6 quyền con AI —
     ssh-field-ai-ask/agent/bypass và console-serial-ai-ask/agent/bypass — không có
     ô tích nào trong Settings nên KHÔNG CẤP ĐƯỢC, và vì collectPermissions dựng lại
     object quyền từ giao diện nên chúng còn bị XOÁ ÂM THẦM mỗi lần admin bấm Lưu.
     Chỉ nhánh customUI==='tool-group' ở trên mới đọc svc.features, nhánh thường thì không. */
  if (svc.features && svc.features.length) page.features = svc.features;
  if (svc.hasCameras) { page.hasCameras = true; page.camClass = svc.camClass || (svc.id + '-cam-cb'); }
  return page;
}
function _regPages(section) {
  return (_REG.services || []).filter(function(s){ return s.section === section; }).map(_regToPage);
}

var SERVICE_HOME_PAGES = _REG ? _regPages('home') : [
  {id:'esxi',        name:'VMware ESXi',    icon:'🖥', perms:['none','read','write']},
  {id:'n8n',         name:'n8n Automation', icon:'⚡', perms:['none','read','write']},
  {id:'casaos',      name:'CasaOS',         icon:'🏠', perms:['none','read','write']},
  {id:'ssh',         name:'SSH Terminal',   icon:'⌨',  perms:['none','write'],  permLabels:{'none':'Không truy cập','write':'Truy cập'}},
  {id:'console-serial', name:'Web Console (Serial)', icon:'🔌', perms:['none','write'], permLabels:{'none':'Không truy cập','write':'Truy cập'}},
  {id:'rustdesk',    name:'RustDesk Remote',icon:'🖥', perms:['none','read'],   permLabels:{'none':'Không truy cập','read':'Truy cập'}},
  {id:'fortigate',   name:'FortiGate',      icon:'🛡', perms:['none','read','write']},

  {id:'asus',        name:'ASUS Router',    icon:'📡', perms:['none','read','write']},
  {type:'services-hub-group', id:'services-hub-group', icon:'🏠', name:'Services Hub (Internal)'},
  {type:'camera-home-group', id:'camera-home-group', icon:'📷', name:'Camera Home'}
];

var PERM_LABELS = {'none':'Không truy cập','read':'Chỉ xem','write':'Toàn quyền'};

/* ═══════════════════════════════════════════════════════════
   DATA STATE
   ═══════════════════════════════════════════════════════════ */
var allUsers = [];
var allGroups = [];
var allUserGroups = [];   // User Groups (gom users)
var allCameras = [];      // Camera Home
var allAuditLog = [];
/* _delegateMode, _delegateServices, DELEGATE_SVC_LABELS declared before initUI() above */
var currentGroupId = null;
var currentUserGroupId = null;
var editingUsername = null;
var currentUserPermUsername = null;

/* ═══════════════════════════════════════════════════════════
   MAIN LOAD ENTRY POINT
   ═══════════════════════════════════════════════════════════ */
function loadSettings() {
  loadUsers();
  loadGroups();
  loadUserGroups();
  loadCameras();
  loadSysConfig();
  loadAuditLog();
  loadMfaStatus();
  loadPasskeys();
}

