/* ══════════════════════════════════════════
   TAB: USER GROUPS
   ══════════════════════════════════════════ */
function loadUserGroups() {
  fetch('/api/admin/user-groups', {cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      allUserGroups = d.groups || [];
      renderUserGroupSidebar();
    })
    .catch(function(){toast('Lỗi tải User Groups','err');});
}

function renderUserGroupSidebar() {
  var el = document.getElementById('ug-sidebar');
  if (!el) return;
  if (!allUserGroups.length) {
    el.innerHTML = '<div class="empty-state" style="padding:2rem 1rem;text-align:center">Chưa có User Group nào.<br><span style="font-size:11px">Nhấn "+ Tạo nhóm" để bắt đầu.</span></div>';
    return;
  }
  el.innerHTML = allUserGroups.map(function(ug){
    var sel = ug.id === currentUserGroupId ? ' selected' : '';
    var memberCount = (ug.members||[]).length;
    var roleGroupCount = (ug.roleGroups||[]).length;
    return '<div class="group-item'+sel+'" onclick="selectUserGroup(\''+esc(ug.id)+'\')">'
      +'<div class="group-item-name">🗂 '+esc(ug.name)+'</div>'
      +(ug.description?'<div class="group-item-desc">'+esc(ug.description)+'</div>':'')
      +'<div class="group-item-meta">'
        +'<span>👥 '+memberCount+' thành viên</span>'
        +'<span>🔐 '+roleGroupCount+' role group</span>'
      +'</div>'
    +'</div>';
  }).join('');
}

function selectUserGroup(id) {
  currentUserGroupId = id;
  renderUserGroupSidebar();
  var ug = allUserGroups.find(function(g){return g.id===id;});
  if (!ug) return;
  renderUserGroupEditor(ug);
}

function renderUserGroupEditor(ug) {
  var el = document.getElementById('ug-editor');
  if (!el) return;
  el.innerHTML = '';

  // ── Title ──
  var header = document.createElement('div');
  header.innerHTML = '<div class="editor-title">🗂 <span style="color:var(--accent)">'+esc(ug.name)+'</span></div>'
    +(ug.description?'<div style="font-size:12px;color:var(--muted);margin-top:4px">'+esc(ug.description)+'</div>':'');
  el.appendChild(header);

  // ── Members Section ──
  var membersSec = document.createElement('div');
  membersSec.style.cssText = 'margin-top:18px;padding-top:16px;border-top:1px solid var(--border-soft)';
  membersSec.innerHTML = '<div style="font-size:13px;font-weight:700;margin-bottom:10px">👥 Thành viên nhóm</div>';

  var memberListDiv = document.createElement('div');
  memberListDiv.id = 'ug-member-list';
  _renderUGMemberList(ug, memberListDiv);
  membersSec.appendChild(memberListDiv);

  // Add member control
  var nonMembers = allUsers.filter(function(u){
    return (ug.members||[]).indexOf(u.username) < 0;
  });
  var addMemberRow = document.createElement('div');
  addMemberRow.style.cssText = 'display:flex;gap:8px;margin-top:10px;align-items:center';
  if (nonMembers.length) {
    addMemberRow.innerHTML = '<select class="inp" id="ug-add-select" style="flex:1;font-size:12px;padding:6px 8px">'
      +'<option value="">— Chọn user để thêm —</option>'
      +nonMembers.map(function(u){return '<option value="'+esc(u.username)+'">'+esc(u.username)+'</option>';}).join('')
      +'</select>'
      +'<button class="btn btn-primary btn-sm" onclick="ugAddMember(\''+esc(ug.id)+'\')">+ Thêm</button>';
  } else {
    addMemberRow.innerHTML = '<span style="font-size:12px;color:var(--muted)">Tất cả users đã là thành viên</span>';
  }
  membersSec.appendChild(addMemberRow);
  el.appendChild(membersSec);

  // ── Role Groups Assignment Section ──
  var roleGroupsSec = document.createElement('div');
  roleGroupsSec.style.cssText = 'margin-top:18px;padding-top:16px;border-top:1px solid var(--border-soft)';
  roleGroupsSec.innerHTML = '<div style="font-size:13px;font-weight:700;margin-bottom:4px">🔐 Gán Role Management Groups</div>'
    +'<div style="font-size:12px;color:var(--muted);margin-bottom:10px">Thành viên nhóm này sẽ tự động nhận quyền từ các Role Group được chọn bên dưới.</div>';

  if (!allGroups.length) {
    roleGroupsSec.innerHTML += '<div style="font-size:12px;color:var(--muted);padding:8px 0">Chưa có Policy Group nào. Vào tab <strong>Role Management</strong> để tạo.</div>';
  } else {
    var rgGrid = document.createElement('div');
    rgGrid.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';
    allGroups.forEach(function(g){
      var checked = (ug.roleGroups||[]).indexOf(g.id) >= 0;
      var lbl = document.createElement('label');
      lbl.className = 'cam-check-label';
      if (checked) lbl.style.cssText = 'border-color:color-mix(in oklch,var(--accent) 40%,transparent);background:color-mix(in oklch,var(--accent) 10%,transparent);color:var(--accent)';
      lbl.innerHTML = '<input type="checkbox" class="ug-rg-cb" value="'+esc(g.id)+'"'+(checked?' checked':'')+'>'
        +'🔐 '+esc(g.name)
        +(g.role?'<span style="font-size:10px;opacity:.75;margin-left:3px">('+esc(g.role)+')</span>':'');
      rgGrid.appendChild(lbl);
    });
    roleGroupsSec.appendChild(rgGrid);
  }
  el.appendChild(roleGroupsSec);

  // ── Save & Delete buttons ──
  var saveRow = document.createElement('div');
  saveRow.style.cssText = 'display:flex;gap:8px;padding-top:16px;border-top:1px solid var(--border-soft);margin-top:16px';
  saveRow.innerHTML = '<button class="btn btn-primary" onclick="saveUserGroup(\''+esc(ug.id)+'\')">💾 Lưu User Group</button>'
    +'<button class="btn btn-danger btn-sm" onclick="confirmDeleteUserGroup(\''+esc(ug.id)+'\')">🗑 Xóa nhóm</button>';
  el.appendChild(saveRow);
}

function _renderUGMemberList(ug, container) {
  var members = ug.members || [];
  if (!members.length) {
    container.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:8px 0">Chưa có thành viên nào</div>';
    return;
  }
  container.innerHTML = '<div style="display:flex;flex-wrap:wrap;gap:6px">'
    +members.map(function(username){
      return '<span style="display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;'
        +'background:color-mix(in oklch,var(--ok) 10%,transparent);border:1px solid color-mix(in oklch,var(--ok) 25%,transparent);'
        +'border-radius:20px;color:var(--text)">'
        +'👤 '+esc(username)
        +'<button onclick="ugRemoveMember(\''+esc(ug.id)+'\',\''+esc(username)+'\')" title="Xóa khỏi nhóm" '
        +'style="background:none;border:none;cursor:pointer;color:var(--muted);font-size:14px;line-height:1;padding:0 0 0 2px">×</button>'
      +'</span>';
    }).join('')
    +'</div>';
}

function ugAddMember(ugid) {
  var sel = document.getElementById('ug-add-select');
  if (!sel || !sel.value) return;
  var username = sel.value;
  var ug = allUserGroups.find(function(g){return g.id===ugid;});
  if (!ug) return;
  var newMembers = (ug.members||[]).concat([username]).filter(function(v,i,a){return a.indexOf(v)===i;});
  _saveUGData(ugid, newMembers, ug.roleGroups||[], function(){
    ug.members = newMembers;
    toast('Đã thêm '+username+' vào nhóm','ok');
    renderUserGroupSidebar();
    renderUserGroupEditor(ug);
  });
}

function ugRemoveMember(ugid, username) {
  var ug = allUserGroups.find(function(g){return g.id===ugid;});
  if (!ug) return;
  var newMembers = (ug.members||[]).filter(function(m){return m!==username;});
  _saveUGData(ugid, newMembers, ug.roleGroups||[], function(){
    ug.members = newMembers;
    toast('Đã xóa '+username+' khỏi nhóm','ok');
    renderUserGroupSidebar();
    renderUserGroupEditor(ug);
  });
}

function saveUserGroup(ugid) {
  var ug = allUserGroups.find(function(g){return g.id===ugid;});
  if (!ug) return;
  var roleGroups = Array.from(document.querySelectorAll('.ug-rg-cb:checked')).map(function(cb){return cb.value;});
  _saveUGData(ugid, ug.members||[], roleGroups, function(){
    ug.roleGroups = roleGroups;
    toast('✓ Đã lưu User Group "'+ug.name+'"','ok');
    renderUserGroupSidebar();
    renderUserGroupEditor(ug);
  });
}

function _saveUGData(ugid, members, roleGroups, onSuccess) {
  fetch('/api/admin/user-groups/'+encodeURIComponent(ugid), {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({members: members, roleGroups: roleGroups})
  }).then(function(r){return r.json();}).then(function(d){
    if (d.error){toast('Lỗi: '+d.error,'err');return;}
    if (onSuccess) onSuccess();
  }).catch(function(e){toast('Lỗi: '+e.message,'err');});
}

function openCreateUserGroup() {
  document.getElementById('ug-modal-name').value = '';
  document.getElementById('ug-modal-desc').value = '';
  document.getElementById('ug-modal-err').classList.remove('show');
  openModal('ug-modal');
  setTimeout(function(){document.getElementById('ug-modal-name').focus();},60);
}

var _ugCreating = false;   // chống double-submit (click/fire 2 lần → tạo 2 group)
function saveNewUserGroup() {
  if (_ugCreating) return;
  var errEl = document.getElementById('ug-modal-err');
  errEl.classList.remove('show');
  var name = document.getElementById('ug-modal-name').value.trim();
  var desc = document.getElementById('ug-modal-desc').value.trim();
  if (!name) { errEl.textContent='Tên nhóm không được để trống'; errEl.classList.add('show'); return; }
  _ugCreating = true;
  fetch('/api/admin/user-groups', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name: name, description: desc})
  }).then(function(r){return r.json();}).then(function(d){
    if (d.error){errEl.textContent=d.error;errEl.classList.add('show');return;}
    closeModal('ug-modal');
    toast('✓ Đã tạo User Group "'+name+'"','ok');
    loadUserGroups();
  }).catch(function(e){errEl.textContent='Lỗi: '+e.message;errEl.classList.add('show');})
    .finally(function(){ _ugCreating = false; });
}

function confirmDeleteUserGroup(ugid) {
  var ug = allUserGroups.find(function(g){return g.id===ugid;});
  if (!ug) return;
  document.getElementById('confirm-title').textContent = 'Xóa User Group';
  document.getElementById('confirm-body').innerHTML = 'Bạn có chắc muốn xóa nhóm <strong>'+esc(ug.name)+'</strong>?<br>'
    +'<span style="font-size:12px;color:var(--muted)">Thành viên sẽ không còn nhận quyền từ nhóm này nữa.</span>';
  document.getElementById('confirm-ok-btn').onclick = function(){
    fetch('/api/admin/user-groups/'+encodeURIComponent(ugid), {method:'DELETE'})
      .then(function(r){return r.json();}).then(function(d){
        closeModal('confirm-modal');
        if (d.error){toast('Lỗi: '+d.error,'err');return;}
        toast('✓ Đã xóa User Group "'+ug.name+'"','ok');
        currentUserGroupId = null;
        var edEl = document.getElementById('ug-editor');
        if (edEl) edEl.innerHTML = '<div class="empty-state" style="padding:4rem 2rem">'
          +'<div style="font-size:2.5rem;margin-bottom:10px">🗂</div>'
          +'<div style="font-size:14px;font-weight:600;margin-bottom:6px">Chọn User Group để chỉnh sửa</div>'
          +'<div style="font-size:12px;color:var(--muted)">Chọn một nhóm ở bên trái để quản lý thành viên và gán Role Group</div>'
        +'</div>';
        loadUserGroups();
      });
  };
  openModal('confirm-modal');
}

/* ═══════════════════════════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════════════════════════ */
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ═══════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════ */
window.addEventListener('DOMContentLoaded', function(){
  var _sp = __USER__.sysPerms || {};
  if (__USER__.isAdmin) {
    // Admin: load everything
    loadSettings();
  } else {
    // Delegated manager or sys-perm user: load based on what they can access
    if ((__USER__.canManagePerms||[]).length > 0 || _sp.addUser || _sp.resetMfa || _sp.blockUser) {
      loadUsers();
    }
    if ((__USER__.canManagePerms||[]).length > 0 || _sp.addUser) {
      loadGroups();
      loadUserGroups();
    }
    if (_sp.systemConfig) loadSysConfig();
    loadMfaStatus();
    loadAuditLog();
  }
  // Điều chỉnh panel "Đổi mật khẩu" theo loại tài khoản
  initAccountTab();
  // Auto-filter numeric input — MFA setup code
  var _mfaSetupEl = document.getElementById('mfa-setup-code');
  if (_mfaSetupEl) {
    _mfaSetupEl.addEventListener('input', function(){ this.value = this.value.replace(/\D/g,''); });
    _mfaSetupEl.addEventListener('keydown', function(e){ if (e.key==='Enter') confirmEnableMfa(); });
  }
  // Auto-filter numeric input — MFA disable code
  var _mfaDisEl = document.getElementById('mfa-disable-code');
  if (_mfaDisEl) {
    _mfaDisEl.addEventListener('input', function(){ this.value = this.value.replace(/\D/g,''); });
    _mfaDisEl.addEventListener('keydown', function(e){ if (e.key==='Enter') confirmDisableMfa(); });
  }
  // Auto-filter numeric input — MFA confirm field in change-password form
  var _accMfaEl = document.getElementById('acc-mfa-code');
  if (_accMfaEl) {
    _accMfaEl.addEventListener('input', function(){ this.value = this.value.replace(/\D/g,''); });
    _accMfaEl.addEventListener('keydown', function(e){ if (e.key==='Enter') changeMyPassword(); });
  }
  // Deep-link từ banner nhắc MFA: /settings.html#setup-mfa → mở tab Tài khoản + bắt đầu thiết lập MFA
  if (location.hash === '#setup-mfa' || location.hash === '#mfa') {
    try { switchTab('account'); } catch(_){}
    setTimeout(function(){
      var b = document.getElementById('btn-enable-mfa');
      if (b && b.style.display !== 'none') { try { startMfaSetup(); } catch(_){} }
      else { var p = document.getElementById('mfa-setup-modal') ? document.querySelector('.panel-title') : null; }
    }, 400);
  }
});

/* ═══════════════════════════════════════════════════════════
   TRỢ LÝ AI — access config
   ═══════════════════════════════════════════════════════════ */
var _AI_ROLES_BASE = ['admin','user','viewer'];
var _aiCfg = { enabled:true, access:{ all:false, roles:['admin'], users:[] } };
function loadAiConfig(){
  fetch('/api/admin/ai-config').then(function(r){return r.json();}).then(function(d){
    _aiCfg = { enabled:d.enabled!==false, access:d.access||{all:false,roles:['admin'],users:[]} };
    document.getElementById('ai-enabled').checked = _aiCfg.enabled;
    document.getElementById('ai-all').checked = !!_aiCfg.access.all;
    document.getElementById('ai-model').textContent = d.model||'HomeAI';
    renderAiRoles();
    if(_allUsers===null) loadAiUsersList(); else renderAiUsers();
  }).catch(function(){});
}
function renderAiRoles(){
  var wrap=document.getElementById('ai-roles');
  var roles=_AI_ROLES_BASE.slice();
  (_aiCfg.access.roles||[]).forEach(function(r){ if(roles.indexOf(r)<0) roles.push(r); });
  wrap.innerHTML = roles.map(function(r){
    var on=(_aiCfg.access.roles||[]).indexOf(r)>=0;
    return '<button class="btn btn-sm" style="border-color:'+(on?'var(--ok)':'var(--border)')+';color:'+(on?'var(--ok)':'var(--text-2)')+'" onclick="aiToggleRole(\''+esc(r)+'\')">'+(on?'✓ ':'')+esc(r)+'</button>';
  }).join('');
}
function aiToggleRole(r){
  var a=_aiCfg.access.roles||[]; var i=a.indexOf(r);
  if(i>=0) a.splice(i,1); else a.push(r);
  _aiCfg.access.roles=a; renderAiRoles();
}
var _allUsers=null;   // [{username, role}]
function loadAiUsersList(){
  fetch('/api/admin/users',{credentials:'include'}).then(function(r){return r.ok?r.json():{users:[]};})
    .then(function(d){ _allUsers=(d.users||[]).map(function(u){return {username:u.username, role:u.role||'user'};}); renderAiUsers(); })
    .catch(function(){ _allUsers=[]; renderAiUsers(); });
}
var _AI_ROLE_COLOR={admin:'var(--accent)',user:'var(--ok)',viewer:'var(--muted)'};
function renderAiUsers(){
  var wrap=document.getElementById('ai-users-list'); if(!wrap) return;
  var sel=_aiCfg.access.users||[];
  if(_allUsers===null){ wrap.innerHTML='<div style="font-size:12px;color:var(--muted);padding:8px">Đang tải danh sách user…</div>'; return; }
  var q=((document.getElementById('ai-user-search')||{}).value||'').trim().toLowerCase();
  var byRole={}, known={};
  _allUsers.forEach(function(u){
    known[u.username]=1;
    if(q && u.username.toLowerCase().indexOf(q)<0) return;
    var r=u.role||'user'; (byRole[r]=byRole[r]||[]).push(u);
  });
  // user đã chọn nhưng không còn trong danh sách (đã xoá / gõ tay trước đây)
  var orphans=sel.filter(function(x){ return !known[x] && (!q || x.toLowerCase().indexOf(q)>=0); });
  var order=['admin','user','viewer'];
  Object.keys(byRole).forEach(function(r){ if(order.indexOf(r)<0) order.push(r); });
  function row(name, role, on){
    return '<label style="display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:6px;cursor:pointer;'+(on?'background:color-mix(in oklch,var(--accent) 14%,transparent)':'')+'">'
      +'<input type="checkbox" '+(on?'checked':'')+' onchange="aiToggleUser(\''+esc(name)+'\')">'
      +'<span style="font-size:13px">'+esc(name)+'</span>'
      +'<span style="margin-left:auto;font-size:10px;padding:1px 8px;border-radius:8px;background:var(--surface-2);color:'+(_AI_ROLE_COLOR[role]||'var(--muted)')+'">'+esc(role)+'</span></label>';
  }
  var html='';
  order.forEach(function(r){
    var arr=byRole[r]; if(!arr||!arr.length) return;
    arr.sort(function(a,b){return a.username.localeCompare(b.username);});
    html+='<div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:8px 4px 3px">'+esc(r)+' · '+arr.length+'</div>';
    html+=arr.map(function(u){ return row(u.username, r, sel.indexOf(u.username)>=0); }).join('');
  });
  if(orphans.length){
    html+='<div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--warn,#e0a000);margin:8px 4px 3px">khác (không còn trong danh sách)</div>';
    html+=orphans.map(function(x){ return row(x,'?',true); }).join('');
  }
  wrap.innerHTML = html || '<div style="font-size:12px;color:var(--muted);padding:8px">Không có user khớp.</div>';
  var sumEl=document.getElementById('ai-users-selected');
  if(sumEl) sumEl.textContent = sel.length ? ('✅ Đã chọn '+sel.length+' user: '+sel.join(', ')) : 'Chưa chọn user cụ thể nào.';
}
function aiToggleUser(name){
  _aiCfg.access.users=_aiCfg.access.users||[];
  var i=_aiCfg.access.users.indexOf(name);
  if(i>=0) _aiCfg.access.users.splice(i,1); else _aiCfg.access.users.push(name);
  renderAiUsers();
}
function saveAiConfig(){
  _aiCfg.enabled=document.getElementById('ai-enabled').checked;
  _aiCfg.access.all=document.getElementById('ai-all').checked;
  fetch('/api/admin/ai-config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(_aiCfg)})
    .then(function(r){return r.json();}).then(function(){ toast&&toast('Đã lưu cấu hình Trợ lý AI'); }).catch(function(){});
}

/* ═══════════════════════════════════════════════════════════
   KẾT NỐI AI — MCP clients / tools / audit
   ═══════════════════════════════════════════════════════════ */
var _mcp = null;
function loadMcp(){
  fetch('/api/admin/mcp').then(function(r){return r.json();}).then(function(d){
    _mcp=d;
    document.getElementById('mcp-enabled').checked = d.enabled!==false;
    document.getElementById('mcp-endpoint').textContent = d.endpoint||'—';
    renderClients(); renderTools(); renderAudit(); renderUnresolved(); renderInsights();
  }).catch(function(){});
}
function renderInsights(){
  var wrap=document.getElementById('mcp-insights');
  if(!wrap) return;
  var list=(_mcp&&_mcp.insights)||[];
  if(!list.length){ wrap.innerHTML='<div class="empty-state">Chưa có đề xuất nào. AI sẽ tự ghi vào đây khi học được điều mới hoặc có ý tưởng cải tiến.</div>'; return; }
  wrap.innerHTML=list.map(function(x){
    var kindChip = x.kind==='suggestion'
      ? '<span class="chip chip-accent" style="font-size:10px">💡 đề xuất cải tiến</span>'
      : x.kind==='observation'
        ? '<span class="chip chip-warn" style="font-size:10px">🔍 tự rà soát</span>'
        : '<span class="chip chip-ok" style="font-size:10px">🎓 điều học được</span>';
    return '<div class="panel-row" style="align-items:flex-start">'
      +'<div style="flex:1;min-width:0">'
        +'<div style="font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap">'+esc(x.title)+' '+kindChip+'</div>'
        +'<div style="font-size:12px;color:var(--text-2);margin-top:4px;white-space:pre-wrap;word-break:break-word">'+esc(x.insight)+'</div>'
        +'<div style="font-size:10px;color:var(--muted);margin-top:3px">'+_relTimeShort(x.time)+'</div>'
      +'</div>'
      +'<div style="display:flex;gap:6px;flex-shrink:0">'
        +'<button class="btn btn-sm btn-primary" onclick="approveInsight(\''+esc(x.id)+'\')" title="Đưa vào kho Dạy AI — AI nhớ vĩnh viễn">✅ Duyệt</button>'
        +'<button class="btn btn-sm btn-danger" onclick="deleteInsight(\''+esc(x.id)+'\')" title="Bỏ đề xuất này">🗑</button>'
      +'</div></div>';
  }).join('');
}
function approveInsight(id){
  fetch('/api/admin/mcp/insights/'+encodeURIComponent(id)+'/approve',{method:'POST'})
    .then(function(r){return r.json();}).then(function(d){
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast('✓ Đã duyệt vào kho Dạy AI ('+(d.path||'')+') — nhớ chạy đồng bộ/reload AI','ok');
      loadMcp(); if(typeof kbLoad==='function'){try{kbLoad();}catch(e){}}
    });
}
function deleteInsight(id){
  fetch('/api/admin/mcp/insights/'+encodeURIComponent(id),{method:'DELETE'}).then(function(){ loadMcp(); });
}
function runReviewNow(){
  toast('Đang rà soát hệ thống…','info');
  fetch('/api/admin/mcp/run-review',{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    if(d.error){toast('Lỗi: '+d.error,'err');return;}
    toast(d.added ? ('✓ Đã tạo bản rà soát '+d.date+' — '+d.count+' điểm cần chú ý') : ('✓ Rà soát xong: '+(d.note||'không có gì đáng chú ý')), d.added?'ok':'info');
    loadMcp();
  }).catch(function(e){ toast('Lỗi: '+e.message,'err'); });
}
function renderUnresolved(){
  var wrap=document.getElementById('mcp-unresolved');
  var list=_mcp.unresolved||[];
  if(!list.length){ wrap.innerHTML='<div class="empty-state">Chưa có câu hỏi nào. AI sẽ ghi vào đây khi không xử lý được.</div>'; return; }
  wrap.innerHTML=list.map(function(u){
    return '<div class="panel-row" style="align-items:flex-start">'
      +'<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:600">'+esc(u.question)+'</div>'
      +(u.reason?'<div style="font-size:11px;color:var(--muted);margin-top:2px">Lý do: '+esc(u.reason)+'</div>':'')
      +'<div style="font-size:10px;color:var(--muted);margin-top:2px">'+_relTimeShort(u.time)+'</div></div>'
      +'<button class="btn btn-sm btn-danger" onclick="deleteUnresolved(\''+esc(u.id)+'\')">✓ Đã xử lý</button></div>';
  }).join('');
}
function deleteUnresolved(id){
  fetch('/api/admin/mcp/unresolved/'+encodeURIComponent(id),{method:'DELETE'}).then(function(){ loadMcp(); });
}
function saveMcpConfig(){
  fetch('/api/admin/mcp/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('mcp-enabled').checked})})
    .then(function(){ toast&&toast('Đã lưu'); });
}
function _relTimeShort(ts){ if(!ts) return 'chưa dùng'; var d=Math.max(0,Date.now()-ts); if(d<60000) return 'vừa xong'; if(d<3600000) return Math.floor(d/60000)+' phút trước'; if(d<86400000) return Math.floor(d/3600000)+' giờ trước'; return Math.floor(d/86400000)+' ngày trước'; }
function renderClients(){
  var wrap=document.getElementById('mcp-clients');
  if(!_mcp.clients.length){ wrap.innerHTML='<div class="empty-state">Chưa có ứng dụng nào. Bấm "+ Thêm ứng dụng" để cấp token.</div>'; return; }
  wrap.innerHTML=_mcp.clients.map(function(c){
    var toolChips=_mcp.tools.map(function(t){
      var on=(c.allowedTools==='*')||(Array.isArray(c.allowedTools)&&c.allowedTools.indexOf(t.name)>=0);
      return '<label class="panel-toggle" style="font-size:11px;margin-right:10px"><input type="checkbox" '+(on?'checked':'')+' onchange="clientToggleTool(\''+esc(c.id)+'\',\''+esc(t.name)+'\',this.checked)"> '+esc(t.label)+'</label>';
    }).join('');
    return '<div style="border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;background:var(--surface)">'
      +'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
        +'<b style="font-size:14px">'+esc(c.name)+'</b>'
        +'<span style="font-size:11px;padding:2px 8px;border-radius:10px;background:'+(c.enabled?'color-mix(in oklch,var(--ok) 12%,transparent)':'var(--surface-2)')+';color:'+(c.enabled?'var(--ok)':'var(--muted)')+'">'+(c.enabled?'hoạt động':'tắt')+'</span>'
        +'<span style="font-size:11px;color:var(--muted);font-family:var(--font-mono)">🔑 ••••'+esc(c.tokenHint)+' · '+_relTimeShort(c.lastUsedAt)+'</span>'
        +'<div style="margin-left:auto;display:flex;gap:6px">'
          +'<label class="panel-toggle" style="font-size:11px"><input type="checkbox" '+(c.enabled?'checked':'')+' onchange="clientSetEnabled(\''+esc(c.id)+'\',this.checked)"> bật</label>'
          +'<button class="btn btn-sm" onclick="clientRegen(\''+esc(c.id)+'\')">↻ Token</button>'
          +'<button class="btn btn-sm btn-danger" onclick="clientDelete(\''+esc(c.id)+'\')">🗑</button>'
        +'</div>'
      +'</div>'
      +'<div style="margin-top:8px;font-size:11px;color:var(--muted)">Công cụ được phép:</div>'
      +'<div style="margin-top:4px">'+toolChips+'</div>'
    +'</div>';
  }).join('');
}
function _clientAllowed(c){ if(c.allowedTools==='*') return _mcp.tools.map(function(t){return t.name;}); return (c.allowedTools||[]).slice(); }
function clientToggleTool(id,tool,on){
  var c=_mcp.clients.find(function(x){return x.id===id;}); if(!c) return;
  var a=_clientAllowed(c); var i=a.indexOf(tool);
  if(on && i<0) a.push(tool); if(!on && i>=0) a.splice(i,1);
  c.allowedTools=a;
  _putClient(id,{allowedTools:a});
}
function clientSetEnabled(id,on){ var c=_mcp.clients.find(function(x){return x.id===id;}); if(c)c.enabled=on; _putClient(id,{enabled:on}).then(function(){renderClients();}); }
function _putClient(id,body){ return fetch('/api/admin/mcp/clients/'+encodeURIComponent(id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}); }
function clientRegen(id){
  if(!confirm('Tạo token mới? Token cũ sẽ ngừng hoạt động ngay.')) return;
  fetch('/api/admin/mcp/clients/'+encodeURIComponent(id)+'/token',{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    if(d.token) _showToken(d.token); loadMcp();
  });
}
function clientDelete(id){ if(!confirm('Xoá ứng dụng này? App sẽ mất quyền truy cập.')) return; fetch('/api/admin/mcp/clients/'+encodeURIComponent(id),{method:'DELETE'}).then(function(){ loadMcp(); }); }
function openAddClient(){
  var name=prompt('Tên ứng dụng AI (vd: OpenClaw):','');
  if(name===null) return; name=(name||'').trim(); if(!name) return;
  fetch('/api/admin/mcp/clients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,allowedTools:_mcp.tools.map(function(t){return t.name;})})})
    .then(function(r){return r.json();}).then(function(d){ if(d.token) _showToken(d.token,d.client&&d.client.name); loadMcp(); });
}
function _showToken(tok,name){
  window.prompt('🔑 Token cho '+(name||'ứng dụng')+' — COPY NGAY (chỉ hiện 1 lần).\nDùng lệnh trên server OpenClaw:\nopenclaw mcp set <name> \'{"headers":{"Authorization":"Bearer <TOKEN>"}}\'', tok);
}
/* Kho công cụ = 3 nhóm: MCP meta (bật/tắt được) + Nguồn ĐỌC dash-read (theo quyền
   user, hiển thị) + HÀNH ĐỘNG dash-action (theo quyền user + xác nhận, hiển thị). */
var _aiReadsList=null,_aiActionsList=null;
function renderTools(){
  var wrap=document.getElementById('mcp-tools');
  var html='<div style="font-size:11px;color:var(--muted);margin:2px 0 6px">🔌 <b>Tool MCP (meta)</b> — AI gọi trực tiếp qua server, không chứa dữ liệu nhạy cảm. Bật/tắt được:</div>';
  html+=_mcp.tools.map(function(t){
    var badge=t.sensitive?'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:color-mix(in oklch,var(--warn,#e0a000) 15%,transparent);color:var(--warn,#e0a000)">nhạy cảm</span>':'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:color-mix(in oklch,var(--ok) 12%,transparent);color:var(--ok)">thường</span>';
    return '<div class="panel-row"><label class="panel-toggle" style="font-size:13px"><input type="checkbox" '+(t.enabled?'checked':'')+' onchange="saveTools()"> <b>'+esc(t.name)+'</b></label>'
      +'<span style="font-size:11px;color:var(--muted)">'+esc(t.dataDesc||'')+'</span> '+badge+'</div>';
  }).join('');
  html+='<div style="font-size:11px;color:var(--muted);margin:12px 0 6px">📖 <b>Nguồn ĐỌC dữ liệu (dash-read)</b> — AI đọc BẰNG QUYỀN của người đang dùng; thiếu quyền là bị chặn:</div>';
  html+=(_aiReadsList||[]).map(function(r){
    return '<div class="panel-row" style="font-size:12px"><b style="font-family:var(--font-mono)">'+esc(r.id)+'</b>'
      +'<span style="font-size:11px;color:var(--muted)">'+esc(r.desc||r.label||'')+'</span>'
      +'<span style="margin-left:auto;font-size:10px;padding:2px 7px;border-radius:8px;background:var(--surface-2);color:var(--muted)">quyền: '+esc(r.perm||'—')+'</span></div>';
  }).join('')||'<div class="empty-state">Đang tải…</div>';
  html+='<div style="font-size:11px;color:var(--muted);margin:12px 0 6px">⚡ <b>HÀNH ĐỘNG (dash-action)</b> — chạy bằng quyền người dùng, việc nguy hiểm LUÔN hỏi xác nhận trên dashboard:</div>';
  html+=(_aiActionsList||[]).map(function(a){
    var p=(a.params||[]).map(function(x){return x.name;}).join(', ');
    return '<div class="panel-row" style="font-size:12px;align-items:flex-start"><div style="min-width:0"><b style="font-family:var(--font-mono)">'+esc(a.id)+'</b>'
      +'<div style="font-size:11px;color:var(--muted)">'+esc(a.desc||'')+(p?' · tham số: '+esc(p):'')+'</div></div>'
      +'<span style="margin-left:auto;display:flex;gap:4px;flex-shrink:0">'
      +(a.adminOnly?'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:color-mix(in oklch,var(--bad,#d33) 12%,transparent);color:var(--bad,#d33)">chỉ admin</span>':'')
      +'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:var(--surface-2);color:var(--muted)">quyền: '+esc(a.perm||'—')+'</span>'
      +'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:color-mix(in oklch,var(--warn,#e0a000) 15%,transparent);color:var(--warn,#e0a000)">'+(a.danger==='confirm'?'xác nhận':'an toàn')+'</span></span></div>';
  }).join('')||'<div class="empty-state">Đang tải…</div>';
  html+='<div style="font-size:11px;color:var(--muted);margin:12px 0 6px">📋 <b>BIỂU MẪU n8n (form_submit)</b> — AI thu thập theo quy tắc, dashboard validate + user xác nhận rồi mới gửi n8n. Sửa bằng nút bên dưới:</div>';
  html+=(_aiFormsList||[]).map(function(f){
    var req=(f.fields||[]).filter(function(x){return x.required;}).map(function(x){return x.name;}).join(', ');
    return '<div class="panel-row" style="font-size:12px;align-items:flex-start"><div style="min-width:0"><b style="font-family:var(--font-mono)">'+esc(f.id)+'</b>'
      +'<div style="font-size:11px;color:var(--muted)">'+esc(f.desc||f.label||'')+(req?' · bắt buộc: '+esc(req):'')+'</div></div>'
      +'<span style="margin-left:auto;display:flex;gap:4px;flex-shrink:0">'
      +(f.adminOnly?'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:color-mix(in oklch,var(--bad,#d33) 12%,transparent);color:var(--bad,#d33)">chỉ admin</span>':'')
      +'<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:var(--surface-2);color:var(--muted)">quyền: '+esc(f.perm||'—')+'</span></span></div>';
  }).join('')||'<div class="empty-state">Chưa có biểu mẫu.</div>';
  html+='<div style="margin-top:8px"><button class="btn btn-sm" onclick="openFormsEditor()">✏️ Sửa biểu mẫu (JSON)</button></div>';
  wrap.innerHTML=html;
}
/* Editor JSON biểu mẫu — admin chỉnh id/fields/pattern/rules/webhookEnv */
function openFormsEditor(){
  fetch('/api/admin/ai-forms',{credentials:'include'}).then(function(r){return r.json();}).then(function(d){
    var cur=JSON.stringify(d.forms||[],null,2);
    var ov=document.createElement('div');
    ov.style.cssText='position:fixed;inset:0;z-index:100002;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:20px';
    ov.innerHTML='<div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;max-width:860px;width:100%;max-height:88vh;display:flex;flex-direction:column;padding:16px">'
      +'<div style="font-weight:700;margin-bottom:6px">📋 Biểu mẫu n8n (JSON)'+(d.usingDefault?' <span style="font-size:11px;color:var(--warn,#e0a000)">— đang dùng mẫu mặc định, lưu sẽ ghi đè vào KV</span>':'')+'</div>'
      +'<div style="font-size:11px;color:var(--muted);margin-bottom:8px">Mỗi form: id, label, desc, perm, adminOnly, webhookEnv (tên secret chứa URL n8n), fields[{name,label,required,pattern,patternDesc,enum,example}], rules (quy tắc chữ cho AI).</div>'
      +'<textarea id="forms-json" style="flex:1;min-height:340px;font-family:var(--font-mono);font-size:12px;background:var(--surface-2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:10px;white-space:pre;overflow:auto"></textarea>'
      +'<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px"><button class="btn" id="forms-cancel">Huỷ</button><button class="btn btn-primary" id="forms-save">💾 Lưu</button></div></div>';
    document.body.appendChild(ov);
    ov.querySelector('#forms-json').value=cur;
    ov.querySelector('#forms-cancel').onclick=function(){ov.remove();};
    ov.querySelector('#forms-save').onclick=function(){
      var v; try{ v=JSON.parse(ov.querySelector('#forms-json').value); }catch(e){ alert('JSON không hợp lệ: '+e.message); return; }
      fetch('/api/admin/ai-forms',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({forms:v})})
        .then(function(r){return r.json();}).then(function(res){
          if(res.ok){ toast&&toast('Đã lưu '+res.count+' biểu mẫu'); ov.remove(); loadAiToolLists(); }
          else alert(res.error||'Lỗi lưu');
        });
    };
  });
}
var _aiFormsList=null;
function loadAiToolLists(){
  Promise.all([
    fetch('/api/ai/reads',{credentials:'include'}).then(function(r){return r.ok?r.json():{reads:[]};}).catch(function(){return {reads:[]};}),
    fetch('/api/ai/actions',{credentials:'include'}).then(function(r){return r.ok?r.json():{actions:[]};}).catch(function(){return {actions:[]};}),
    fetch('/api/ai/forms',{credentials:'include'}).then(function(r){return r.ok?r.json():{forms:[]};}).catch(function(){return {forms:[]};}),
  ]).then(function(rs){ _aiReadsList=rs[0].reads||[]; _aiActionsList=rs[1].actions||[]; _aiFormsList=rs[2].forms||[]; if(_mcp) renderTools(); });
}
function saveTools(){
  var boxes=document.querySelectorAll('#mcp-tools input[type="checkbox"]');
  var body={};
  _mcp.tools.forEach(function(t,i){ body[t.name]=boxes[i]?boxes[i].checked:true; });
  fetch('/api/admin/mcp/tools',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(){ toast&&toast('Đã lưu công cụ'); });
}
function renderAudit(){
  var wrap=document.getElementById('mcp-audit');
  if(!_mcp.audit||!_mcp.audit.length){ wrap.innerHTML='<div class="empty-state">Chưa có lần gọi nào.</div>'; return; }
  wrap.innerHTML=_mcp.audit.map(function(a){
    return '<div class="panel-row" style="font-size:12px"><span>'+esc(a.clientName||a.clientId||'?')+' gọi <b>'+esc(a.tool||'')+'</b></span>'
      +'<span style="margin-left:auto;color:var(--muted)">'+_relTimeShort(a.time)+' · <span style="color:'+(a.ok?'var(--ok)':'var(--bad)')+'">'+(a.ok?'ok':'chặn')+'</span></span></div>';
  }).join('');
}
/* (đã gỡ hàm toast no-op — nó đè hàm toast thật ở trên khiến MỌI thông báo trên
   trang Settings bị câm. Giờ dùng chung hàm toast(msg,cls) hiển thị #toast.) */

/* ═══════════════════════════════════════════════════════════
   AI HUB — sub-nav + load-all
   ═══════════════════════════════════════════════════════════ */
function loadAi(){ loadMcp(); loadAiToolLists(); loadAiConfig(); loadKb(); }
function aiSub(sub, btn){
  document.querySelectorAll('#tc-ai .ai-subtab').forEach(function(b){b.classList.remove('active');});
  document.querySelectorAll('#tc-ai .ai-pane').forEach(function(p){p.classList.remove('active');});
  if(btn) btn.classList.add('active');
  var pane=document.getElementById('aip-'+sub); if(pane) pane.classList.add('active');
}

/* ═══════════════════════════════════════════════════════════
   DẠY AI — kho kiến thức (KB) dạng cây thư mục
   ═══════════════════════════════════════════════════════════ */
var _kb=[], _kbCur=null;
function loadKb(){
  fetch('/api/admin/mcp/kb').then(function(r){return r.json();}).then(function(d){
    _kb=(d&&d.files)||[]; renderKbTree();
  }).catch(function(){});
}
function renderKbTree(){
  var wrap=document.getElementById('kb-tree'); if(!wrap) return;
  if(!_kb.length){ wrap.innerHTML='<div class="empty-state">Chưa có file. Gõ đường dẫn (vd network/vlan.md) rồi bấm + Tạo.</div>'; return; }
  // group by folder
  var groups={};
  _kb.forEach(function(f){
    var i=f.path.lastIndexOf('/');
    var dir=i>=0?f.path.slice(0,i):''; var name=i>=0?f.path.slice(i+1):f.path;
    (groups[dir]=groups[dir]||[]).push({name:name,path:f.path});
  });
  var html='';
  Object.keys(groups).sort().forEach(function(dir){
    if(dir) html+='<div style="font-size:11px;color:var(--muted);margin:6px 0 2px">📁 '+esc(dir)+'</div>';
    groups[dir].forEach(function(f){
      var on=(_kbCur===f.path);
      html+='<div onclick="kbOpen(\''+esc(f.path)+'\')" style="padding:4px 8px;border-radius:6px;cursor:pointer;'+(on?'background:color-mix(in oklch,var(--accent) 12%,transparent);color:var(--accent)':'')+(dir?';margin-left:12px':'')+'">📄 '+esc(f.name)+'</div>';
    });
  });
  wrap.innerHTML=html;
}
function kbOpen(path){
  var f=_kb.find(function(x){return x.path===path;});
  _kbCur=path;
  document.getElementById('kb-cur').textContent=path;
  document.getElementById('kb-content').value=f?f.content:'';
  document.getElementById('kb-content').disabled=false;
  document.getElementById('kb-save').disabled=false;
  document.getElementById('kb-del').disabled=!f;
  renderKbTree();
}
function kbNew(){
  var inp=document.getElementById('kb-newpath'); var p=(inp.value||'').trim();
  if(!p){ inp.focus(); return; }
  _kbCur=p; inp.value='';
  document.getElementById('kb-cur').textContent=p+' (mới — bấm Lưu)';
  document.getElementById('kb-content').value=''; document.getElementById('kb-content').disabled=false;
  document.getElementById('kb-save').disabled=false; document.getElementById('kb-del').disabled=true;
  document.getElementById('kb-content').focus();
}
function kbSave(){
  if(!_kbCur) return;
  var content=document.getElementById('kb-content').value;
  fetch('/api/admin/mcp/kb',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:_kbCur,content:content})})
    .then(function(r){return r.json();}).then(function(d){
      if(d.error){ alert(d.error); return; }
      _kbCur=d.path||_kbCur; toast&&toast('Đã lưu '+_kbCur); loadKb();
      document.getElementById('kb-cur').textContent=_kbCur;
      document.getElementById('kb-del').disabled=false;
    });
}
function kbDelete(){
  if(!_kbCur) return;
  if(!confirm('Xoá file "'+_kbCur+'"?')) return;
  fetch('/api/admin/mcp/kb/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:_kbCur})})
    .then(function(){ _kbCur=null; document.getElementById('kb-cur').textContent='Chọn hoặc tạo một file…';
      document.getElementById('kb-content').value=''; document.getElementById('kb-content').disabled=true;
      document.getElementById('kb-save').disabled=true; document.getElementById('kb-del').disabled=true; loadKb(); });
}
function kbSyncInfo(){
  var origin=location.origin;
  var cmd='# Chạy trên máy OpenClaw (thay <TOKEN> bằng token MCP). Đồng bộ KB → workspace:\n'
    +'mkdir -p /home/administrator/.openclaw/workspace/kb\n'
    +'curl -s -H "Authorization: Bearer <TOKEN>" '+origin+'/api/ai/knowledge \\\n'
    +'  | jq -r \'.files[] | @base64\' | while read r; do\n'
    +'    p=$(echo "$r"|base64 -d|jq -r .path); c=$(echo "$r"|base64 -d|jq -r .content)\n'
    +'    mkdir -p "/home/administrator/.openclaw/workspace/kb/$(dirname "$p")"\n'
    +'    printf \'%s\' "$c" > "/home/administrator/.openclaw/workspace/kb/$p"\n'
    +'  done\n'
    +'chown -R administrator:administrator /home/administrator/.openclaw/workspace/kb\n'
    +'# rồi: sudo systemctl restart openclaw';
  window.prompt('Lệnh đồng bộ KB xuống máy OpenClaw (copy chạy trên server đó):', cmd);
}
