/* ══════════════════════════════════════════
   TAB 1: USER MANAGEMENT
   ══════════════════════════════════════════ */
function loadUsers() {
  fetch('/api/admin/users',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      allUsers = d.users || [];
      if (d.delegateMode) { _delegateMode = true; _delegateServices = _normalizeDelegateSvcs(d.canManagePerms); }
      renderUsers();
    })
    .catch(function(){toast('Lỗi tải user list','err');});
}

function renderUsers() {
  var tbody = document.getElementById('user-tbody');
  var q = ((document.getElementById('user-search') || {}).value || '').trim().toLowerCase();
  var list = q ? allUsers.filter(function(u){ return (u.username||'').toLowerCase().indexOf(q) !== -1; }) : allUsers;
  if (!allUsers.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Chưa có user nào</td></tr>';
    return;
  }
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Không tìm thấy user "'+q+'"</td></tr>';
    return;
  }
  // ── Delegated user mode: simplified table ──
  if (_delegateMode) {
    tbody.innerHTML = list.map(function(u){
      var isAdminAcc = (u.role === 'admin');
      var roleChip = isAdminAcc
        ? '<span class="badge badge-admin">Admin</span>'
        : '<span class="badge badge-user">User</span>';
      var permSummary = _delegateServices.map(function(s){
        var v = (u.permissions||{})[s] || 'none';
        var color = v==='write'?'var(--ok)':v==='read'?'var(--accent)':'var(--muted)';
        return '<span style="font-size:10px;padding:1px 6px;border-radius:10px;border:1px solid '+color+';color:'+color+'">'
          +(DELEGATE_SVC_LABELS[s]||s)+': '+v+'</span>';
      }).join(' ');
      // Admin accounts: locked — show "Tài khoản gốc" badge, no action buttons
      var _dSp = __USER__.sysPerms || {};
      var _dCanReset = !!_dSp.resetMfa;
      var _dCanBlock = !!_dSp.blockUser;
      var actionCell = isAdminAcc
        ? '<span style="font-size:11px;color:var(--muted);font-style:italic">⭐ Tài khoản gốc</span>'
        : (function(){
            var btns = [];
            if (_delegateServices.length > 0) btns.push('<button class="btn btn-outline btn-sm" onclick="openUserPerms(\''+esc(u.username)+'\')">🔑 Quyền</button>');
            if (_dCanReset && u.mfaEnabled) btns.push('<button class="btn btn-outline btn-sm" onclick="adminResetMfa(\''+esc(u.username)+'\')" style="color:var(--accent);border-color:color-mix(in oklch,var(--accent) 35%,transparent)">🔄 Reset MFA</button>');
            if (_dCanBlock) btns.push(u.blocked
              ? '<button class="btn btn-outline btn-sm" onclick="blockUser(\''+esc(u.username)+'\',true)" style="color:var(--ok);border-color:color-mix(in oklch,var(--ok) 30%,transparent)">✅ Bỏ chặn</button>'
              : '<button class="btn btn-outline btn-sm" onclick="blockUser(\''+esc(u.username)+'\',false)" style="color:#f87171;border-color:rgba(239,68,68,.35)">🚫 Chặn</button>');
            return btns.join(' ');
          }());
      var dBlockedBadge = u.blocked ? '<span title="Bị chặn bởi '+(u.blockedBy||'admin')+'" style="margin-left:6px;font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.4)">🚫 Blocked</span>' : '';
      return '<tr>'
        +'<td><div class="user-avatar" style="width:32px;height:32px;font-size:13px;display:grid;place-items:center">'+esc((u.username||'?').charAt(0).toUpperCase())+'</div></td>'
        +'<td><span style="font-weight:600">'+esc(u.username)+'</span>'+(isAdminAcc?' <span style="font-size:10px;padding:1px 6px;border-radius:10px;background:color-mix(in oklch,var(--bad) 10%,transparent);color:var(--bad);border:1px solid color-mix(in oklch,var(--bad) 25%,transparent)">Protected</span>':'')+dBlockedBadge+'</td>'
        +'<td>'+roleChip+'</td>'
        +'<td colspan="2"><div style="display:flex;flex-wrap:wrap;gap:4px">'+permSummary+'</div></td>'
        +'<td style="text-align:right">'+actionCell+'</td>'
      +'</tr>';
    }).join('');
    return;
  }

  tbody.innerHTML = list.map(function(u){
    var groups = (u.groups||[]).map(function(g){return '<span class="chip chip-accent">📋 '+esc(g)+'</span>';}).join('');
    var ugChips = (u.userGroups||[]).map(function(g){return '<span class="chip" style="border-color:rgba(20,184,166,.3);color:#2dd4bf;background:rgba(20,184,166,.08)">🗂 '+esc(g)+'</span>';}).join('');
    var allGroupChips = ugChips + groups;
    var roleChip = u.role==='admin'
      ? '<span class="badge badge-admin">Admin</span>'
      : '<span class="badge badge-user">User</span>';
    // Locked status badge
    var _viewerSp = __USER__.sysPerms || {};
    var _viewerIsAdmin = !!__USER__.isAdmin;
    var _canResetMfa = _viewerIsAdmin || !!_viewerSp.resetMfa;
    var _canBlockUser = _viewerIsAdmin || !!_viewerSp.blockUser;
    var _hasFullDelegate = _viewerIsAdmin || ((__USER__.canManagePerms||[]).length > 0) || !!_viewerSp.addUser;
    var lockedBadge = u.locked
      ? '<span title="Bị khóa'+(u.lockedAt?' lúc '+new Date(u.lockedAt).toLocaleString('vi-VN'):'')+'" style="margin-left:6px;font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.3)">🔒 Locked'+(u.loginAttempts?'('+u.loginAttempts+'x)':'')+'</span>'
      : (u.loginAttempts > 0 ? '<span style="margin-left:6px;font-size:10px;color:var(--warn)">⚠ '+u.loginAttempts+' lần sai</span>' : '');
    var blockedBadge = u.blocked
      ? '<span title="Bị chặn bởi '+(u.blockedBy||'admin')+(u.blockedAt?' lúc '+new Date(u.blockedAt).toLocaleString('vi-VN'):'')+'" style="margin-left:6px;font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.4)">🚫 Blocked</span>'
      : '';
    // Admin account: cannot be edited or deleted — show lock badge instead of action buttons
    var isRootAdmin = (u.username === 'admin');
    var isMicrosoft = !!(u.microsoftEmail);
    var azureBadge = isMicrosoft
      ? '<span class="chip-azure" style="margin-left:6px" title="Đăng nhập qua Microsoft Azure: '+esc(u.microsoftEmail||'')+'">☁ Azure</span>'
      : '';
    var emailSub = isMicrosoft
      ? '<div style="font-size:11px;color:#60a5fa;margin-top:2px;opacity:.85">'+esc(u.microsoftEmail)+'</div>'
      : '';
    // Delegation badge: user được ủy quyền quản lý (service delegation hoặc quyền hệ thống)
    var _sp = u.sysPerms || {};
    var _isDelegated = ((u.canManagePerms||[]).length > 0) || _sp.addUser || _sp.systemConfig || _sp.resetMfa || _sp.blockUser;
    var delegateBadge = (_isDelegated && !isRootAdmin)
      ? '<span title="Được ủy quyền quản lý / quyền hệ thống" style="margin-left:6px;font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(168,85,247,.15);color:#c084fc;border:1px solid rgba(168,85,247,.4)">🛡 Ủy quyền</span>'
      : '';
    var unlockBtn = (_viewerIsAdmin && !isRootAdmin && u.locked)
      ? '<button class="btn btn-outline btn-sm" onclick="unlockUser(\''+esc(u.username)+'\')" style="color:var(--ok);border-color:color-mix(in oklch,var(--ok) 30%,transparent)">🔓 Mở khóa</button>'
      : '';
    var resetMfaBtn = (_canResetMfa && !isRootAdmin && u.mfaEnabled)
      ? '<button class="btn btn-outline btn-sm" onclick="resetUserMfa(\''+esc(u.username)+'\')" style="color:var(--warn);border-color:color-mix(in oklch,var(--warn) 30%,transparent)" title="Xóa MFA — user phải thiết lập lại khi đăng nhập">🔑 Reset MFA</button>'
      : '';
    // Tái dùng CHÍNH XÁC quyền resetMfa — Passkey/MFA cùng nhóm "khôi phục đăng nhập"
    var resetPasskeyBtn = (_canResetMfa && !isRootAdmin && u.webauthnCount > 0)
      ? '<button class="btn btn-outline btn-sm" onclick="resetUserWebauthn(\''+esc(u.username)+'\')" style="color:var(--warn);border-color:color-mix(in oklch,var(--warn) 30%,transparent)" title="Xóa tất cả Passkey — dùng khi user mất/quên hết thiết bị">🔐 Reset Passkey ('+u.webauthnCount+')</button>'
      : '';
    var blockBtn = (_canBlockUser && !isRootAdmin)
      ? (u.blocked
          ? '<button class="btn btn-outline btn-sm" onclick="blockUser(\''+esc(u.username)+'\',true)" style="color:var(--ok);border-color:color-mix(in oklch,var(--ok) 30%,transparent)" title="Bỏ chặn user này">✅ Bỏ chặn</button>'
          : '<button class="btn btn-outline btn-sm" onclick="blockUser(\''+esc(u.username)+'\',false)" style="color:#f87171;border-color:rgba(239,68,68,.35)" title="Chặn user — không thể đăng nhập (local + Azure)">🚫 Chặn</button>')
      : '';
    var editPermsDeleteBtns = (_hasFullDelegate && !isRootAdmin)
      ? '<button class="btn btn-outline btn-sm" onclick="openEditUser(\''+esc(u.username)+'\')">✏ Sửa</button>'
        +'<button class="btn btn-outline btn-sm" onclick="openUserPerms(\''+esc(u.username)+'\')">🔑 Quyền</button>'
        +((_viewerIsAdmin || (u.createdBy && u.createdBy === __USER__.username)) ? '<button class="btn btn-danger btn-sm" onclick="confirmDeleteUser(\''+esc(u.username)+'\')" title="Xóa user do bạn tạo">✕</button>' : '')
      : '';
    var actionCell = isRootAdmin
      ? '<td style="text-align:right"><span style="font-size:11px;color:var(--muted);font-style:italic">⭐ Tài khoản gốc</span></td>'
      : '<td style="text-align:right"><div style="display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">'
          +unlockBtn
          +resetMfaBtn
          +resetPasskeyBtn
          +blockBtn
          +editPermsDeleteBtns
        +'</div></td>';
    return '<tr>'
      +'<td><div class="user-avatar" style="width:32px;height:32px;font-size:13px;display:grid;place-items:center">'+esc((u.username||'?').charAt(0).toUpperCase())+'</div></td>'
      +'<td><div><div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px"><span style="font-weight:600">'+esc(u.username)+'</span>'+(isRootAdmin?'<span class="chip chip-accent" style="font-size:10px">Super Admin</span>':'')+azureBadge+delegateBadge+lockedBadge+blockedBadge+'</div>'+emailSub+'</div></td>'
      +'<td>'+roleChip+'</td>'
      +'<td><div style="display:flex;flex-wrap:wrap;gap:4px">'+(allGroupChips||'<span style="color:var(--muted);font-size:12px">—</span>')+'</div></td>'
      +actionCell
    +'</tr>';
  }).join('');
}

function unlockUser(username) {
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/unlock', { method:'POST' })
    .then(function(r){ return r.json(); })
    .then(function(d) {
      if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
      toast('✓ Đã mở khóa '+username, 'ok');
      var u = allUsers.find(function(x){ return x.username===username; });
      if (u) { u.locked=false; u.loginAttempts=0; u.lockedAt=null; renderUsers(); }
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

function resetUserMfa(username) {
  if (!confirm('Reset MFA cho "'+username+'"?\n\n• Secret MFA + recovery codes hiện tại sẽ bị xóa\n• User sẽ bị đăng xuất\n• Lần đăng nhập sau user phải thiết lập lại MFA\n\nDùng khi user mất điện thoại / authenticator.')) return;
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/reset-mfa', { method:'POST' })
    .then(_apiJson).then(function(d){
      if (!d) return;
      if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
      toast('✓ Đã reset MFA cho '+username+'. User sẽ thiết lập lại khi đăng nhập.', 'ok');
      var u = allUsers.find(function(x){ return x.username===username; });
      if (u) { u.mfaEnabled=false; renderUsers(); }
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

function resetUserWebauthn(username) {
  if (!confirm('Xoá TẤT CẢ passkey của "'+username+'"?\n\nUser sẽ không đăng nhập bằng vân tay/FaceID được nữa cho tới khi đăng ký lại. Mật khẩu vẫn dùng bình thường.\n\nDùng khi user mất hết thiết bị / quên.')) return;
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/reset-webauthn', { method:'POST' })
    .then(_apiJson).then(function(d){
      if (!d) return;
      if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
      toast('✓ Đã xoá '+d.removed+' passkey của '+username+'.', 'ok');
      var u = allUsers.find(function(x){ return x.username===username; });
      if (u) { u.webauthnCount=0; renderUsers(); }
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

function blockUser(username, currentlyBlocked) {
  var action = currentlyBlocked ? 'bỏ chặn' : 'chặn';
  var warn = currentlyBlocked
    ? 'User sẽ có thể đăng nhập lại bình thường.'
    : '• User bị chặn sẽ KHÔNG thể đăng nhập (cả local lẫn Azure SSO)\n• Session hiện tại của user sẽ bị đăng xuất ngay\n• Admin có thể bỏ chặn bất kỳ lúc nào';
  if (!confirm((currentlyBlocked ? 'Bỏ chặn' : 'Chặn')+' tài khoản "'+username+'"?\n\n'+warn)) return;
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ blocked: !currentlyBlocked })
  })
    .then(_apiJson).then(function(d){
      if (!d) return;
      if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
      var msg = currentlyBlocked ? '✓ Đã bỏ chặn '+username : '🚫 Đã chặn '+username+'. User bị đăng xuất ngay.';
      toast(msg, currentlyBlocked ? 'ok' : 'warn');
      var u = allUsers.find(function(x){ return x.username===username; });
      if (u) { u.blocked=!currentlyBlocked; if(!currentlyBlocked){u.blockedAt=Date.now();} else {u.blockedAt=null;u.blockedBy=null;} renderUsers(); }
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

function onLoginTypeChange(val) {
  var isAzure = (val === 'azure');
  document.getElementById('um-block-local').style.display = isAzure ? 'none' : '';
  document.getElementById('um-block-azure').style.display = isAzure ? '' : 'none';
}

function openAddUser() {
  if (!__USER__.isAdmin && !(__USER__.sysPerms && __USER__.sysPerms.addUser)) {
    toast('Bạn không có quyền tạo user', 'err');
    return;
  }
  editingUsername = null;
  document.getElementById('user-modal-title').textContent = '+ Thêm User Mới';
  document.getElementById('user-modal-save').textContent = 'Tạo user';
  document.getElementById('um-login-time-section').style.display = 'none';
  document.getElementById('um-session-ttl-section').style.display = 'none';
  // Reset local block
  document.getElementById('um-username').value = '';
  document.getElementById('um-username').disabled = false;
  document.getElementById('um-password').value = '';
  document.getElementById('um-pw-label').textContent = 'Mật khẩu';
  document.getElementById('um-role').value = 'user';
  // MFA toggle — chỉ hiện khi tạo mới, mặc định bật
  var mfaRow = document.getElementById('um-mfa-row');
  if (mfaRow) mfaRow.style.display = '';
  document.getElementById('um-require-mfa').checked = true;
  // Reset azure block
  document.getElementById('um-ms-email').value = '';
  document.getElementById('um-username-az').value = '';
  document.getElementById('um-role-az').value = 'user';
  // Default: local
  document.getElementById('um-login-type').value = 'local';
  onLoginTypeChange('local');
  document.getElementById('user-modal-err').classList.remove('show');
  renderGroupCheckboxes('um-groups-list', []);
  renderGroupCheckboxes('um-groups-list-az', []);
  openModal('user-modal');
  document.getElementById('um-username').focus();
}

function openEditUser(username) {
  var u = allUsers.find(function(x){return x.username===username;});
  if (!u) return;
  editingUsername = username;
  document.getElementById('user-modal-title').textContent = '✏ Sửa User: ' + username;
  document.getElementById('user-modal-save').textContent = 'Lưu thay đổi';
  document.getElementById('user-modal-err').classList.remove('show');
  // Ẩn MFA toggle khi edit (chỉ áp dụng lúc tạo mới)
  var mfaRowEdit = document.getElementById('um-mfa-row');
  if (mfaRowEdit) mfaRowEdit.style.display = 'none';

  var loginType = u.microsoftEmail ? 'azure' : 'local';
  document.getElementById('um-login-type').value = loginType;
  onLoginTypeChange(loginType);

  if (loginType === 'azure') {
    // Azure block
    document.getElementById('um-ms-email').value = u.microsoftEmail || '';
    document.getElementById('um-username-az').value = username;
    document.getElementById('um-role-az').value = u.role || 'user';
    renderGroupCheckboxes('um-groups-list-az', u.groups||[]);
    // Local block (reset, không dùng)
    document.getElementById('um-username').value = username;
    document.getElementById('um-username').disabled = true;
    document.getElementById('um-password').value = '';
    document.getElementById('um-role').value = u.role || 'user';
    renderGroupCheckboxes('um-groups-list', u.groups||[]);
  } else {
    // Local block
    document.getElementById('um-username').value = username;
    document.getElementById('um-username').disabled = true;
    document.getElementById('um-password').value = '';
    document.getElementById('um-pw-label').textContent = 'Đổi mật khẩu (để trống nếu không đổi)';
    document.getElementById('um-role').value = u.role || 'user';
    renderGroupCheckboxes('um-groups-list', u.groups||[]);
    // Azure block (reset)
    document.getElementById('um-ms-email').value = '';
    document.getElementById('um-username-az').value = username;
    document.getElementById('um-role-az').value = u.role || 'user';
    renderGroupCheckboxes('um-groups-list-az', u.groups||[]);
  }

  // ── Session TTL (edit mode only) ──
  var stSection = document.getElementById('um-session-ttl-section');
  if (stSection) {
    stSection.style.display = '';
    var stSel = document.getElementById('um-session-ttl');
    var stVal = u.sessionTtlHours || 0;
    // Pick nearest option
    var stOpts = [0,8,24,72,168,360,720];
    stSel.value = stOpts.includes(stVal) ? stVal : 0;
  }

  // ── Login time restriction (edit mode only) ──
  var ltSection = document.getElementById('um-login-time-section');
  if (ltSection) {
    ltSection.style.display = '';
    var ltOn = !!u.loginTimeEnabled;
    var ltCb = document.getElementById('um-login-time-enabled');
    if (ltCb) ltCb.checked = ltOn;
    document.getElementById('um-lt-status').textContent = ltOn ? '🟢 Đang bật' : '⚪ Đang tắt';
    var ltTrack = document.getElementById('um-lt-track');
    if (ltTrack) ltTrack.classList.toggle('on', ltOn);
    document.getElementById('um-login-time-body').style.display = ltOn ? '' : 'none';
    document.getElementById('um-lt-start').value = u.loginTimeStart || '06:00';
    document.getElementById('um-lt-end').value   = u.loginTimeEnd   || '23:00';
    document.getElementById('um-lt-tz').value    = u.loginTimeZone  || 'Asia/Ho_Chi_Minh';
  }
  openModal('user-modal');
}

function toggleUmLoginTime(on) {
  document.getElementById('um-lt-status').textContent = on ? '🟢 Đang bật' : '⚪ Đang tắt';
  var track = document.getElementById('um-lt-track');
  if (track) track.classList.toggle('on', on);
  document.getElementById('um-login-time-body').style.display = on ? '' : 'none';
}

function renderGroupCheckboxes(containerId, selectedGroups) {
  var container = document.getElementById(containerId);
  if (!allGroups.length) {
    container.innerHTML = '<span style="font-size:12px;color:var(--muted)">Chưa có nhóm nào</span>';
    return;
  }
  container.innerHTML = allGroups.map(function(g){
    var checked = selectedGroups.indexOf(g.id) >= 0;
    return '<label class="cam-check-label">'
      +'<input type="checkbox" class="um-group-cb" value="'+esc(g.id)+'"'+(checked?' checked':'')+'>'
      +esc(g.name)
    +'</label>';
  }).join('');
}

function saveUser() {
  var errEl = document.getElementById('user-modal-err');
  errEl.classList.remove('show');
  var loginType = document.getElementById('um-login-type').value;
  var isAzure = (loginType === 'azure');

  // Đọc dữ liệu từ đúng block đang hiển thị
  var username, password, role, groups, msEmail;
  if (isAzure) {
    msEmail  = (document.getElementById('um-ms-email').value || '').trim().toLowerCase();
    role     = document.getElementById('um-role-az').value;
    groups   = Array.from(document.getElementById('um-groups-list-az').querySelectorAll('.um-group-cb:checked')).map(function(cb){return cb.value;});
    // username: khi edit dùng hidden field; khi tạo mới tự derive từ email
    username = editingUsername || document.getElementById('um-username-az').value.trim() ||
               msEmail.split('@')[0].toLowerCase().replace(/[^a-z0-9_\-]/g,'_').replace(/_+/g,'_').replace(/^_|_$/g,'') || 'azuser';
    password = '';
  } else {
    username = editingUsername || document.getElementById('um-username').value.trim().toLowerCase();
    password = document.getElementById('um-password').value;
    role     = document.getElementById('um-role').value;
    groups   = Array.from(document.getElementById('um-groups-list').querySelectorAll('.um-group-cb:checked')).map(function(cb){return cb.value;});
    msEmail  = '';
  }

  if (!editingUsername && !isAzure && !username) { errEl.textContent='Username không được để trống'; errEl.classList.add('show'); return; }
  if (!editingUsername && !isAzure && !password)  { errEl.textContent='Mật khẩu không được để trống'; errEl.classList.add('show'); return; }
  if (!editingUsername && isAzure  && !msEmail)   { errEl.textContent='Email Microsoft không được để trống'; errEl.classList.add('show'); return; }

  var btn = document.getElementById('user-modal-save');
  btn.disabled = true; btn.textContent = 'Đang lưu...';

  if (editingUsername) {
    // Update: change password (nếu local & có nhập) + groups + role + microsoft email + login time
    // Run sequentially (not parallel) to prevent read-modify-write race on the same KV user key.
    // e.g. login-time update must NOT overwrite the role change committed by the groups/role update.
    var taskFns = [];
    if (!isAzure && password) {
      taskFns.push(function(){return fetch('/api/admin/users/'+encodeURIComponent(editingUsername),{
        method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({password:password})
      }).then(function(r){return r.json();});});
    }
    taskFns.push(function(){return fetch('/api/admin/users/'+encodeURIComponent(editingUsername)+'/groups',{
      method:'PUT',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({groups:groups, role:role})
    }).then(function(r){return r.json();});});
    // Save Microsoft email (link hoặc unlink)
    var currentMsEmail = (allUsers.find(function(u){return u.username===editingUsername;})||{}).microsoftEmail||'';
    var newMsEmail = isAzure ? msEmail : '';
    if (newMsEmail !== (currentMsEmail||'').toLowerCase()) {
      taskFns.push(function(){return fetch('/api/admin/users/'+encodeURIComponent(editingUsername)+'/microsoft-email',{
        method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({microsoftEmail: newMsEmail || null})
      }).then(function(r){return r.json();});});
    }
    // Save login time restriction — must run AFTER groups/role to avoid overwriting role change
    var ltCb = document.getElementById('um-login-time-enabled');
    if (ltCb) {
      taskFns.push(function(){return fetch('/api/admin/users/'+encodeURIComponent(editingUsername)+'/login-time',{
        method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
          loginTimeEnabled: ltCb.checked,
          loginTimeStart:   document.getElementById('um-lt-start').value || '06:00',
          loginTimeEnd:     document.getElementById('um-lt-end').value   || '23:00',
          loginTimeZone:    document.getElementById('um-lt-tz').value    || 'Asia/Ho_Chi_Minh',
        })
      }).then(function(r){return r.json();});});
    }
    // Save session TTL per-user
    var stSel = document.getElementById('um-session-ttl');
    if (stSel) {
      taskFns.push(function(){return fetch('/api/admin/users/'+encodeURIComponent(editingUsername)+'/session-ttl',{
        method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ sessionTtlHours: Number(stSel.value) })
      }).then(function(r){return r.json();});});
    }

    taskFns.reduce(function(chain, fn){
      return chain.then(function(results){ return fn().then(function(r){ results.push(r); return results; }); });
    }, Promise.resolve([])).then(function(results){
      btn.disabled=false; btn.textContent='Lưu thay đổi';
      var hasErr = results.find(function(r){return r && r.error;});
      if (hasErr) { errEl.textContent=hasErr.error; errEl.classList.add('show'); return; }
      closeModal('user-modal');
      toast('✓ Đã cập nhật user '+editingUsername,'ok');
      loadUsers();
    }).catch(function(e){
      btn.disabled=false; btn.textContent='Lưu thay đổi';
      errEl.textContent='Lỗi: '+e.message; errEl.classList.add('show');
    });
  } else {
    // Tạo user mới
    var requireMfa = !isAzure ? document.getElementById('um-require-mfa').checked : true;
    var createBody = {username: username, password: password || crypto.randomUUID(), groups: groups, requireMfa: requireMfa};
    if (!_delegateMode) { createBody.role = role; }
    fetch('/api/admin/users',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(createBody)
    }).then(function(r){return r.json();}).then(function(d){
      if(d.error){btn.disabled=false;btn.textContent='Tạo user';errEl.textContent=d.error;errEl.classList.add('show');return;}
      // Nếu Azure → link email ngay sau khi tạo
      if (isAzure && msEmail) {
        return fetch('/api/admin/users/'+encodeURIComponent(username)+'/microsoft-email',{
          method:'PUT',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({microsoftEmail: msEmail})
        }).then(function(r){return r.json();}).then(function(d2){
          btn.disabled=false; btn.textContent='Tạo user';
          if(d2.error){closeModal('user-modal');toast('✓ Tạo user '+username+' (cảnh báo: '+d2.error+')','warn');loadUsers();return;}
          closeModal('user-modal');
          toast('✓ Đã tạo user '+username+' và liên kết Azure email','ok');
          loadUsers();
        });
      }
      btn.disabled=false; btn.textContent='Tạo user';
      closeModal('user-modal');
      toast('✓ Đã tạo user '+username,'ok');
      loadUsers();
    }).catch(function(e){
      btn.disabled=false; btn.textContent='Tạo user';
      errEl.textContent=_giaiThichLoiMang(e); errEl.classList.add('show');
    });
  }
}

/* "Failed to fetch" = fetch BỊ TỪ CHỐI, KHÔNG có mã lỗi HTTP nào — nghĩa là yêu cầu chưa
   tới được máy chủ. Trên dashboard này, nguyên nhân số một là PHIÊN CLOUDFLARE ACCESS HẾT
   HẠN: Cloudflare chặn ở tầng biên rồi chuyển hướng sang trang đăng nhập của nó ở origin
   khác, không có header CORS → trình duyệt chặn.
   Anh Thoại gặp đúng lỗi này lúc tạo user (2026-08-20) và không thể đoán ra từ dòng
   "Lỗi: Failed to fetch" trơ trọi. Đổi thành câu nói rõ phải làm gì. */
function _giaiThichLoiMang(e){
  var m = (e && e.message) || String(e);
  if (/failed to fetch|networkerror|load failed/i.test(m)) {
    return 'Không gửi được yêu cầu — nhiều khả năng phiên Cloudflare Access đã hết hạn. '
         + 'Hãy TẢI LẠI TRANG (F5), đăng nhập lại rồi thử lại. (Chi tiết kỹ thuật: ' + m + ')';
  }
  return 'Lỗi: ' + m;
}

function confirmDeleteUser(username) {
  document.getElementById('confirm-title').textContent = 'Xóa User';
  document.getElementById('confirm-body').innerHTML = 'Bạn có chắc muốn xóa user <strong>'+esc(username)+'</strong>?<br>Hành động này không thể hoàn tác.';
  document.getElementById('confirm-ok-btn').onclick = function(){
    fetch('/api/admin/users/'+encodeURIComponent(username),{method:'DELETE'})
      .then(function(r){return r.json();}).then(function(d){
        closeModal('confirm-modal');
        if(d.error){toast('Lỗi: '+d.error,'err');return;}
        toast('✓ Đã xóa user '+username,'ok');
        loadUsers();
      });
  };
  openModal('confirm-modal');
}

/* ── Individual user permission override ── */
function openUserPerms(username) {
  currentUserPermUsername = username;
  var isAdmin = __USER__.isAdmin;
  // Block delegated users from editing admin accounts
  if (_delegateMode && !isAdmin) {
    var targetUser = allUsers.find(function(u){return u.username===username;});
    if (targetUser && targetUser.role === 'admin') {
      toast('Không thể chỉnh quyền của tài khoản Admin', 'err');
      return;
    }
  }
  var title = _delegateMode
    ? '🔑 Chỉnh quyền ' + (_delegateServices.length > 0 ? _delegateServices.map(function(s){return DELEGATE_SVC_LABELS[s]||s;}).join(', ') + ' cho: ' : 'của: ') + username
    : '🔑 Quyền riêng của: ' + username;
  document.getElementById('user-perm-title').textContent = title;
  document.getElementById('user-perm-panel').style.display = '';
  document.getElementById('user-perm-editor').innerHTML = '<div style="padding:1rem 0;color:var(--muted);font-size:13px">⏳ Đang tải quyền...</div>';
  // Hide/show delegate section based on role
  document.getElementById('user-perm-delegate').style.display = isAdmin ? '' : 'none';
  document.getElementById('user-perm-panel').scrollIntoView({behavior:'smooth',block:'start'});
  // Always fetch fresh data from server to show current saved permissions
  fetch('/api/admin/users', {cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      allUsers = d.users || [];
      if (d.delegateMode) { _delegateMode = true; _delegateServices = _normalizeDelegateSvcs(d.canManagePerms); }
      renderUsers();
      var u = allUsers.find(function(x){return x.username===username;});
      if (!u) {
        document.getElementById('user-perm-editor').innerHTML = '<div class="empty-state">Không tìm thấy user</div>';
        return;
      }
      if (_delegateMode) {
        // Block if target user is an admin
        if (u.role === 'admin') {
          document.getElementById('user-perm-editor').innerHTML = '<div style="padding:12px 14px;border-radius:8px;background:color-mix(in oklch,var(--bad) 8%,transparent);border:1px solid color-mix(in oklch,var(--bad) 25%,transparent);font-size:13px;color:var(--text)">⭐ Đây là <strong>Tài khoản gốc (Admin)</strong> — không thể chỉnh quyền.</div>';
          return;
        }
        // Delegated user: only show the services they can manage
        _renderDelegatePermEditor(u);
      } else {
        renderPermEditor('user-perm-editor', u.permissions||{}, u.panels||{}, u.cameras||[], 'usr');
        // Show warning if user is in a Role Management group (their individual perms are overridden)
        var roleGroups = (u.groups||[]).map(function(gid){
          return allGroups.find(function(g){ return g.id===gid; });
        }).filter(function(g){ return g && g.role; });
        if (roleGroups.length > 0) {
          var grpNames = roleGroups.map(function(g){
            var rl = g.role === 'admin' ? '👑 admin' : '👤 user';
            return '"'+esc(g.name)+'" ('+rl+')';
          }).join(', ');
          var warnEl = document.createElement('div');
          warnEl.style.cssText = 'margin-bottom:14px;padding:10px 14px;border-radius:8px;background:color-mix(in oklch,var(--warn) 10%,transparent);border:1px solid color-mix(in oklch,var(--warn) 40%,transparent)';
          warnEl.innerHTML = '<div style="font-size:12px;font-weight:700;color:var(--warn);margin-bottom:4px">⚠️ User đang thuộc nhóm Role Management</div>'
            +'<div style="font-size:12px;line-height:1.6;color:var(--text)">Nhóm: <strong>'+grpNames+'</strong><br>'
            +'Role của nhóm có <strong>ưu tiên cao nhất</strong> và ghi đè toàn bộ — các quyền riêng bên dưới <strong>không có tác dụng</strong> khi user thuộc nhóm có role.</div>';
          document.getElementById('user-perm-editor').prepend(warnEl);
        }
        // Admin: also render delegation section
        if (isAdmin) _renderDelegateSvcSection(u);
      }
    })
    .catch(function(e){
      document.getElementById('user-perm-editor').innerHTML = '<div class="empty-state">Lỗi tải dữ liệu: '+esc(e.message)+'</div>';
    });
}

/* Render a restricted permission editor showing only the delegated services */
function _renderDelegatePermEditor(u) {
  var el = document.getElementById('user-perm-editor');
  el.innerHTML = '';
  var perms = u.permissions || {};
  var wrapper = document.createElement('div');
  wrapper.style.cssText = 'display:flex;flex-direction:column;gap:8px';
  _delegateServices.forEach(function(svc) {
    var curPerm = perms[svc] || 'none';
    var row = document.createElement('div');
    row.className = 'perm-row';
    row.id = 'usr-row-' + svc;
    var svcName = DELEGATE_SVC_LABELS[svc] || svc;
    var radios = ['none','read','write'].map(function(p){
      var lbl = PERM_LABELS[p] || p;
      var chk = (curPerm===p) ? ' checked' : '';
      return '<label class="perm-radio-label"><input type="radio" name="usr-perm-'+svc+'" value="'+p+'"'+chk+'>'+lbl+'</label>';
    }).join('');
    row.innerHTML = '<span class="perm-row-icon">🔑</span><span class="perm-row-name">'+esc(svcName)+'</span><div class="perm-radios">'+radios+'</div>';
    wrapper.appendChild(row);
  });
  el.appendChild(wrapper);
}

/* Render the delegation section (admin view only): checkboxes grouped by Home / Movi */
function _renderDelegateSvcSection(u) {
  var el = document.getElementById('user-perm-delegate-list');
  if (!el) return;
  var current = u.canManagePerms || [];

  function renderGroup(id, icon, title, svcs) {
    var checks = svcs.map(function(svc){
      var checked = current.indexOf(svc) >= 0;
      return '<label class="cam-check-label">'
        +'<input type="checkbox" class="delegate-svc-cb" value="'+esc(svc)+'"'+(checked?' checked':'')+'>'
        +esc(DELEGATE_SVC_LABELS[svc]||svc)
        +'</label>';
    }).join('');
    var checkedCount = svcs.filter(function(s){ return current.indexOf(s) >= 0; }).length;
    var badge = checkedCount > 0
      ? ' <span style="font-size:10px;font-weight:600;padding:1px 7px;border-radius:10px;background:color-mix(in oklch,var(--warn) 15%,transparent);color:var(--warn);border:1px solid color-mix(in oklch,var(--warn) 30%,transparent)">'+checkedCount+'/'+svcs.length+'</span>'
      : ' <span style="font-size:10px;color:var(--muted)">'+svcs.length+' services</span>';
    return '<div class="dlg-group">'
      +'<div class="dlg-group-hdr open" onclick="toggleDlgGroup(this)">'
        +'<span>'+icon+' '+title+badge+'</span>'
        +'<span class="dlg-arrow">▼</span>'
      +'</div>'
      +'<div class="dlg-group-body">'+checks+'</div>'
    +'</div>';
  }

  var currentSys = u.sysPerms || {};
  var sysSection = '<div class="dlg-group" style="margin-top:10px;border-color:color-mix(in oklch,var(--accent) 30%,transparent)">'
    +'<div class="dlg-group-hdr open" onclick="toggleDlgGroup(this)" style="background:color-mix(in oklch,var(--accent) 6%,transparent)">'
      +'<span>⚙ Hệ thống (System)</span>'
      +'<span class="dlg-arrow">▼</span>'
    +'</div>'
    +'<div class="dlg-group-body">'
      +'<label class="cam-check-label" style="flex-direction:column;align-items:flex-start;gap:2px">'
        +'<span style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="delegate-sys-cb" value="addUser"'+(currentSys.addUser?' checked':'')+'> Tạo User</span>'
        +'<span style="font-size:11px;color:var(--muted);margin-left:22px">Cho phép tạo user mới (bao gồm đặt giới hạn giờ đăng nhập)</span>'
      +'</label>'
      +'<label class="cam-check-label" style="flex-direction:column;align-items:flex-start;gap:2px">'
        +'<span style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="delegate-sys-cb" value="systemConfig"'+(currentSys.systemConfig?' checked':'')+'> System Config</span>'
        +'<span style="font-size:11px;color:var(--muted);margin-left:22px">Cho phép xem và cấu hình trang System Config (session, idle timeout, email, v.v.)</span>'
      +'</label>'
      +'<label class="cam-check-label" style="flex-direction:column;align-items:flex-start;gap:2px">'
        +'<span style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="delegate-sys-cb" value="resetMfa"'+(currentSys.resetMfa?' checked':'')+'> Reset MFA</span>'
        +'<span style="font-size:11px;color:var(--muted);margin-left:22px">Cho phép admin reset MFA của user khác (không áp dụng cho tài khoản admin)</span>'
      +'</label>'
      +'<label class="cam-check-label" style="flex-direction:column;align-items:flex-start;gap:2px">'
        +'<span style="display:flex;align-items:center;gap:6px"><input type="checkbox" class="delegate-sys-cb" value="blockUser"'+(currentSys.blockUser?' checked':'')+'> Chặn / Bỏ chặn User</span>'
        +'<span style="font-size:11px;color:var(--muted);margin-left:22px">Cho phép chặn hoặc bỏ chặn user (local + Azure SSO), không áp dụng cho tài khoản admin</span>'
      +'</label>'
    +'</div>'
  +'</div>';

  el.innerHTML =
    renderGroup('home','🏠','Service Home',_DELEGATE_HOME) +
    renderGroup('movi','🏢','Service Movi',_DELEGATE_MOVI) +
    sysSection;
}

function toggleDlgGroup(hdr) {
  hdr.classList.toggle('open');
  var body = hdr.nextElementSibling;
  if (body) body.classList.toggle('hidden');
}

/* Save canManagePerms + sysPerms for current user (admin only) */
function saveManagePerms() {
  if (!currentUserPermUsername) return;
  var username = currentUserPermUsername;
  var svcCbs = document.querySelectorAll('.delegate-svc-cb:checked');
  var canManagePerms = Array.from(svcCbs).map(function(cb){return cb.value;});
  var sysCbs = document.querySelectorAll('.delegate-sys-cb');
  var sysPerms = {};
  Array.from(sysCbs).forEach(function(cb){ if (cb.checked) sysPerms[cb.value] = true; });
  // Save sequentially to avoid KV race condition (both endpoints read-modify-write same key)
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/manage-perms', {
    method: 'PUT', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({canManagePerms: canManagePerms})
  }).then(function(r){return r.json();})
  .then(function(r1) {
    if (r1 && r1.error) { toast('Lỗi: '+r1.error, 'err'); return Promise.reject(null); }
    return fetch('/api/admin/users/'+encodeURIComponent(username)+'/sys-perms', {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({sysPerms: sysPerms})
    }).then(function(r){return r.json();});
  })
  .then(function(r2) {
    if (!r2) return;
    if (r2.error) { toast('Lỗi: '+r2.error, 'err'); return; }
    toast('✓ Đã lưu ủy quyền cho ' + username, 'ok');
    loadUsers();
  })
  .catch(function(e){ if (e) toast('Lỗi: '+e.message,'err'); });
}

function closeUserPermPanel() {
  document.getElementById('user-perm-panel').style.display = 'none';
  currentUserPermUsername = null;
}

function saveUserPerms() {
  if (!currentUserPermUsername) return;
  var username = currentUserPermUsername;
  var saveBtn = document.querySelector('#user-perm-panel .btn-primary');
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = '⏳ Đang lưu...'; }

  if (_delegateMode) {
    // Delegated user mode: only send the services in _delegateServices
    var delegatePerms = {};
    _delegateServices.forEach(function(svc){
      var radios = document.querySelectorAll('input[name="usr-perm-'+svc+'"]');
      for (var i=0; i<radios.length; i++) {
        if (radios[i].checked) { delegatePerms[svc] = radios[i].value; break; }
      }
    });
    fetch('/api/admin/users/'+encodeURIComponent(username)+'/permissions', {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({permissions: delegatePerms})
    }).then(function(r){return r.json();}).then(function(d){
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu quyền'; }
      if (d.error) { toast('Lỗi: '+d.error,'err'); return; }
      toast('✓ Đã lưu quyền cho ' + username, 'ok');
      var u = allUsers.find(function(x){return x.username===username;});
      if (u) { Object.assign(u.permissions, delegatePerms); renderUsers(); }
    }).catch(function(e){
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu quyền'; }
      toast('Lỗi: '+e.message,'err');
    });
    return;
  }

  var result = collectPermissions('usr');

  // ONE atomic call: permissions + panels + cameras saved together → no KV race condition
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/panels', {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      permissions: result.permissions,
      panels:      result.panels,
      cameras:     result.cameras
    })
  }).then(function(r){return r.json();}).then(function(d) {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu quyền'; }
    if (d.error) { toast('Lỗi: ' + d.error, 'err'); return; }
    toast('✓ Đã lưu quyền riêng cho ' + username, 'ok');
    // Re-render immediately from what we just saved — no KV consistency delay
    renderPermEditor('user-perm-editor', result.permissions, result.panels, result.cameras, 'usr');
    // Update local allUsers cache so the table reflects the change too
    var u = allUsers.find(function(x){return x.username===username;});
    if (u) {
      u.permissions = result.permissions;
      u.panels      = result.panels;
      u.cameras     = result.cameras;
      renderUsers();
    }
  }).catch(function(e) {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu quyền'; }
    toast('Lỗi: ' + e.message, 'err');
  });
}

/* ══════════════════════════════════════════
   TAB 2: SYSTEM CONFIG
   ══════════════════════════════════════════ */
function loadSysConfig() {
  fetch('/api/system-config',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      // Status display cards
      document.getElementById('cfg-session-disp').innerHTML = d.sessionTtlHours+' <span class="cfg-unit">giờ</span>';
      document.getElementById('cfg-idle-disp').innerHTML = d.idleTimeoutMin+' <span class="cfg-unit">phút</span>';
      document.getElementById('cfg-maxusers-disp').textContent = d.maxUsers;
      document.getElementById('cfg-audit-disp').innerHTML = d.auditRetentionDays+' <span class="cfg-unit">ngày</span>';
      // Inputs — existing
      document.getElementById('cfg-session').value = d.sessionTtlHours;
      document.getElementById('cfg-idle').value = d.idleTimeoutMin;
      document.getElementById('cfg-maxusers').value = d.maxUsers;
      document.getElementById('cfg-audit-ret').value = d.auditRetentionDays;
      document.getElementById('cfg-default-role').value = d.defaultRole || 'user';
      document.getElementById('cfg-banner').value = d.loginBannerMsg || '';
      document.getElementById('cfg-dashboard-title').value = d.dashboardTitle || '';
      document.getElementById('cfg-pw-minlen').value = d.pwMinLength ?? 6;
      document.getElementById('cfg-max-attempts').value = d.maxLoginAttempts ?? 8;
      // Maintenance mode
      var mOn = !!d.maintenanceMode;
      var cb = document.getElementById('cfg-maintenance');
      if (cb) cb.checked = mOn;
      var track = document.getElementById('maint-track');
      if (track) { track.classList.toggle('warn-on', mOn); track.classList.remove('on'); }
      var st = document.getElementById('maint-status-text');
      if (st) st.textContent = mOn ? '🔴 Đang bật' : '⚪ Đang tắt';
      var msgRow = document.getElementById('maint-msg-row');
      if (msgRow) msgRow.style.display = mOn ? '' : 'none';
      var mi = document.getElementById('cfg-maint-msg');
      if (mi) mi.value = d.maintenanceMsg || '';
      // ── New security fields ──
      document.getElementById('cfg-lockout-min').value = d.lockoutDurationMin ?? 15;
      document.getElementById('cfg-pw-expiry').value = d.pwExpiryDays ?? 0;
      document.getElementById('cfg-max-sessions').value = d.maxConcurrentSessions ?? 0;
      // IP Binding toggle
      var ipbOn = !!d.enforceIpBinding;
      var ipbCb = document.getElementById('cfg-ipbinding');
      if (ipbCb) ipbCb.checked = ipbOn;
      var ipbTrack = document.getElementById('ipbind-track');
      if (ipbTrack) { ipbTrack.classList.toggle('warn-on', ipbOn); ipbTrack.classList.remove('on'); }
      var ipbSt = document.getElementById('ipbind-status-text');
      if (ipbSt) ipbSt.textContent = ipbOn ? '🔴 Đang bật' : '⚪ Đang tắt';
      // IP Whitelist
      var wl = Array.isArray(d.ipWhitelist) ? d.ipWhitelist.join('\n') : '';
      document.getElementById('cfg-ip-whitelist').value = wl;
      // Login background
      document.getElementById('cfg-bg-type').value = d.loginBgType || 'none';
      document.getElementById('cfg-bg-value').value = d.loginBgValue || '';
      toggleBgValue();
      // Email notifications
      var emOn = !!d.emailEnabled;
      var emCb = document.getElementById('cfg-email-enabled');
      if (emCb) emCb.checked = emOn;
      document.getElementById('email-enabled-text').textContent = emOn ? '🟢 Đang bật' : '⚪ Đang tắt';
      var emTrack = document.getElementById('email-toggle-track');
      if (emTrack) emTrack.classList.toggle('on', emOn);
      document.getElementById('email-config-body').style.display = emOn ? '' : 'none';
      document.getElementById('cfg-email-webhook').value = d.emailWebhook || '';
      document.getElementById('cfg-email-admin').value = d.emailAdminAddress || '';
      var evts = d.emailEvents || {};
      ['login_success','login_fail','account_locked','force_logout_all','maintenance_toggle','password_changed','password_expired'].forEach(function(k){
        var el = document.getElementById('evt-'+k);
        if (el) el.checked = !!evts[k];
      });
      // Runtime info
      var ri = document.getElementById('cfg-runtime-info');
      ri.innerHTML = d.updatedAt
        ? '📝 Cập nhật lần cuối bởi <strong>'+esc(d.updatedBy||'?')+'</strong> lúc '+new Date(d.updatedAt).toLocaleString('vi-VN')
        : 'Chưa có thay đổi nào.';
    })
    .catch(function(){document.getElementById('cfg-runtime-info').textContent='Lỗi tải config';});
}

function toggleBgValue() {
  var t = document.getElementById('cfg-bg-type').value;
  var v = document.getElementById('cfg-bg-value');
  if (t === 'none') { v.disabled = true; v.placeholder = ''; }
  else if (t === 'color') { v.disabled = false; v.placeholder = 'vd: #1e293b'; }
  else { v.disabled = false; v.placeholder = 'https://example.com/bg.jpg'; }
}

function _apiJson(r) {
  if (r.status === 401) { toast('Phiên đăng nhập hết hạn — đang chuyển về trang đăng nhập...', 'err'); setTimeout(function(){ location.href = '/'; }, 1500); return null; }
  return r.json();
}

function toggleEmailConfig(on) {
  document.getElementById('email-enabled-text').textContent = on ? '🟢 Đang bật' : '⚪ Đang tắt';
  var track = document.getElementById('email-toggle-track');
  if (track) track.classList.toggle('on', on);
  document.getElementById('email-config-body').style.display = on ? '' : 'none';
  // Auto-save ngay lập tức (giống Maintenance toggle)
  fetch('/api/system-config', { method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ emailEnabled: on }) })
    .then(_apiJson)
    .then(function(d) {
      if (!d) return;
      if (d.error) { toast('Lỗi lưu: '+d.error, 'err'); return; }
      toast(on ? '🟢 Đã bật Email Notifications' : '⚪ Đã tắt Email Notifications', on ? 'ok' : 'info');
    })
    .catch(function(e) { toast('Lỗi: '+e.message, 'err'); });
}

function forceLogoutAll() {
  if (!confirm('Xác nhận kick TẤT CẢ phiên đăng nhập đang active?\n\nPhiên của bạn sẽ được giữ lại. Tất cả người dùng khác sẽ bị đăng xuất ngay lập tức.')) return;
  fetch('/api/admin/force-logout-all', { method: 'POST' })
    .then(function(r){ return r.json(); })
    .then(function(d) {
      if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
      toast('✓ Đã kick '+d.kicked+' phiên đăng nhập', 'ok');
      loadSessions();
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

/* ── Active sessions ── */
function _fmtWhen(ts){ if(!ts) return '—'; var d=new Date(ts); return d.toLocaleString('vi-VN',{hour:'2-digit',minute:'2-digit',day:'2-digit',month:'2-digit'}); }
function loadSessions() {
  var tb = document.getElementById('sess-tbody');
  tb.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--muted)">Đang tải…</td></tr>';
  fetch('/api/admin/sessions').then(_apiJson).then(function(d){
    if (!d) return;
    if (d.error) { tb.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--bad)">'+esc(d.error)+'</td></tr>'; return; }
    document.getElementById('sess-count').textContent = '· '+d.total;
    if (!d.sessions.length) { tb.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--muted)">Không có phiên nào</td></tr>'; return; }
    tb.innerHTML = d.sessions.map(function(s){
      var meth = s.authMethod==='microsoft' ? '🪟 Microsoft' : '🔑 Local';
      var cur = s.current ? ' <span style="font-size:10px;color:var(--ok);border:1px solid var(--ok);border-radius:4px;padding:1px 5px;margin-left:4px">PHIÊN NÀY</span>' : '';
      var btn = s.current ? '<span style="color:var(--muted);font-size:11px">—</span>'
        : '<button class="btn btn-danger btn-sm" onclick="kickSession(\''+s.sid+'\',\''+esc(s.username)+'\')">Kick</button>';
      return '<tr style="border-top:1px solid var(--border-soft)">'
        + '<td style="padding:9px 12px;font-weight:500">'+esc(s.username)+cur+'</td>'
        + '<td style="padding:9px 12px;font-family:var(--font-mono);color:var(--muted)">'+esc(s.ip)+'</td>'
        + '<td style="padding:9px 12px">'+meth+'</td>'
        + '<td style="padding:9px 12px;color:var(--muted)">'+_fmtWhen(s.createdAt)+'</td>'
        + '<td style="padding:9px 12px;text-align:center">'+btn+'</td>'
      + '</tr>';
    }).join('');
  }).catch(function(e){ tb.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--bad)">Lỗi: '+esc(e.message)+'</td></tr>'; });
}
function kickSession(sid, uname) {
  if (!confirm('Kick phiên đăng nhập của "'+uname+'"?\nNgười dùng này sẽ bị đăng xuất ngay.')) return;
  fetch('/api/admin/sessions/'+sid, { method:'DELETE' }).then(_apiJson).then(function(d){
    if (!d) return;
    if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
    toast('✓ Đã kick phiên của '+d.kicked, 'ok');
    loadSessions();
  }).catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

/* ── Backup / Restore ── */
function downloadBackup() {
  toast('Đang tạo backup…', 'ok');
  fetch('/api/admin/backup').then(function(r){
    if (!r.ok) return r.json().then(function(d){ throw new Error(d.error||('HTTP '+r.status)); });
    var fn = 'dashboard-backup.json';
    var cd = r.headers.get('Content-Disposition'); var m = cd && cd.match(/filename="([^"]+)"/); if (m) fn = m[1];
    return r.blob().then(function(b){ return { b:b, fn:fn }; });
  }).then(function(x){
    var url = URL.createObjectURL(x.b);
    var a = document.createElement('a'); a.href = url; a.download = x.fn; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
    toast('✓ Đã tải file backup', 'ok');
  }).catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}
function restoreFromFile(input) {
  var f = input.files && input.files[0]; input.value = '';
  if (!f) return;
  var reader = new FileReader();
  reader.onload = function() {
    var data; try { data = JSON.parse(reader.result); } catch(e) { toast('File không phải JSON hợp lệ', 'err'); return; }
    var nUsers = (data.userlist && data.userlist.length) || 0;
    var when = (data._meta && data._meta.exportedAt) ? new Date(data._meta.exportedAt).toLocaleString('vi-VN') : '?';
    if (!confirm('⚠️ KHÔI PHỤC CẤU HÌNH\n\nFile: '+nUsers+' users · xuất lúc '+when+'\n\nToàn bộ users, nhóm quyền, system config hiện tại sẽ bị GHI ĐÈ. Không thể hoàn tác.\n\nTiếp tục?')) return;
    data.confirm = true;
    fetch('/api/admin/restore', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) })
      .then(_apiJson).then(function(d){
        if (!d) return;
        if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
        toast('✓ Đã khôi phục '+d.users+' users. Đang tải lại…', 'ok');
        setTimeout(function(){ location.reload(); }, 1500);
      }).catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
  };
  reader.readAsText(f);
}

function testEmailWebhook() {
  var wh = document.getElementById('cfg-email-webhook').value.trim();
  if (!wh) { toast('Vui lòng nhập webhook URL trước', 'err'); return; }
  var btn = document.querySelector('button[onclick="testEmailWebhook()"]');
  var origText = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Đang gửi...'; }
  // Save current config first so latest webhook URL is persisted
  var body = collectSysConfig();
  body.emailEnabled = true;
  fetch('/api/system-config', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) })
    .then(_apiJson)
    .then(function(d) {
      if (!d) return;
      if (d.error) { toast('Lỗi lưu config: '+d.error, 'err'); return; }
      // Use dedicated test endpoint — sends event:"test" directly without side effects
      return fetch('/api/admin/test-email', { method: 'POST' })
        .then(_apiJson)
        .then(function(r) {
          if (!r) return;
          if (r.error) { toast('Lỗi test webhook: '+r.error, 'err'); return; }
          toast('✓ Test đã gửi — kiểm tra n8n & email', 'ok');
        });
    })
    .catch(function(e){ toast('Lỗi: '+e.message, 'err'); })
    .finally(function(){ if (btn) { btn.disabled = false; btn.textContent = origText; } });
}

function toggleMaintenance(on) {
  var track = document.getElementById('maint-track');
  if (track) { track.classList.toggle('warn-on', on); track.classList.remove('on'); }
  var st = document.getElementById('maint-status-text');
  if (st) st.textContent = on ? '🔴 Đang bật' : '⚪ Đang tắt';
  var msgRow = document.getElementById('maint-msg-row');
  if (msgRow) msgRow.style.display = on ? '' : 'none';
  fetch('/api/system-config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({maintenanceMode:on})})
    .then(_apiJson)
    .then(function(d){
      if(!d)return;
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast(on ? '🚧 Đã bật Maintenance Mode' : '✓ Đã tắt Maintenance Mode', on ? 'warn' : 'ok');
    })
    .catch(function(e){toast('Lỗi: '+e.message,'err');});
}

function toggleIpBinding(on) {
  var track = document.getElementById('ipbind-track');
  if (track) { track.classList.toggle('warn-on', on); track.classList.remove('on'); }
  var st = document.getElementById('ipbind-status-text');
  if (st) st.textContent = on ? '🔴 Đang bật' : '⚪ Đang tắt';
  fetch('/api/system-config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({enforceIpBinding:on})})
    .then(_apiJson)
    .then(function(d){
      if(!d)return;
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast(on ? '🔒 Đã bật khóa phiên theo IP — user nào đang ở IP khác lúc đăng nhập sẽ phải đăng nhập lại' : '✓ Đã tắt khóa phiên theo IP', on ? 'warn' : 'ok');
    })
    .catch(function(e){toast('Lỗi: '+e.message,'err');});
}

function saveMaintMsg() {
  var msg = (document.getElementById('cfg-maint-msg').value || '').trim();
  fetch('/api/system-config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({maintenanceMsg:msg})})
    .then(_apiJson)
    .then(function(d){
      if(!d)return;
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast('✓ Đã lưu thông báo bảo trì','ok');
    })
    .catch(function(e){toast('Lỗi: '+e.message,'err');});
}

function collectSysConfig() {
  // IP whitelist: textarea → array of non-empty lines
  var rawWl = (document.getElementById('cfg-ip-whitelist').value || '').split('\n');
  var ipWhitelist = rawWl.map(function(s){return s.trim();}).filter(Boolean);
  // Email events
  var emailEvents = {};
  ['login_success','login_fail','account_locked','force_logout_all','maintenance_toggle','password_changed','password_expired'].forEach(function(k){
    var el = document.getElementById('evt-'+k);
    emailEvents[k] = el ? el.checked : false;
  });
  return {
    sessionTtlHours:      Number(document.getElementById('cfg-session').value),
    idleTimeoutMin:       Number(document.getElementById('cfg-idle').value),
    maxUsers:             Number(document.getElementById('cfg-maxusers').value),
    auditRetentionDays:   Number(document.getElementById('cfg-audit-ret').value),
    defaultRole:          document.getElementById('cfg-default-role').value,
    loginBannerMsg:       document.getElementById('cfg-banner').value.trim(),
    dashboardTitle:       document.getElementById('cfg-dashboard-title').value.trim(),
    pwMinLength:          Number(document.getElementById('cfg-pw-minlen').value) || 6,
    maxLoginAttempts:     Number(document.getElementById('cfg-max-attempts').value) || 8,
    // ── New fields ──
    lockoutDurationMin:   Number(document.getElementById('cfg-lockout-min').value) || 0,
    pwExpiryDays:         Number(document.getElementById('cfg-pw-expiry').value) || 0,
    maxConcurrentSessions:Number(document.getElementById('cfg-max-sessions').value) || 0,
    ipWhitelist:          ipWhitelist,
    loginBgType:          document.getElementById('cfg-bg-type').value,
    loginBgValue:         document.getElementById('cfg-bg-value').value.trim(),
    emailEnabled:         document.getElementById('cfg-email-enabled').checked,
    emailWebhook:         document.getElementById('cfg-email-webhook').value.trim(),
    emailAdminAddress:    document.getElementById('cfg-email-admin').value.trim(),
    emailEvents:          emailEvents,
  };
}

function saveSysConfig() {
  var body = collectSysConfig();
  fetch('/api/system-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(_apiJson)
    .then(function(d){
      if(!d)return;
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast('✓ Đã lưu cấu hình hệ thống','ok');
      loadSysConfig();
    })
    .catch(function(e){toast('Lỗi: '+e.message,'err');});
}

/* ══════════════════════════════════════════
   TAB 3: AUDIT LOG
   ══════════════════════════════════════════ */
var _auditRaw = [];
function loadAuditLog() {
  document.getElementById('audit-list').innerHTML = '<div class="empty-state">Đang tải...</div>';
  fetch('/api/activity',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      _auditRaw = d.log || [];
      var days = d.cutoffDays || 30;
      document.getElementById('audit-total-info').textContent = _auditRaw.length + ' bản ghi (' + days + ' ngày)';
      renderAuditLog(_auditRaw);
    })
    .catch(function(){document.getElementById('audit-list').innerHTML='<div class="empty-state">Lỗi tải audit log</div>';});
}

function filterAuditLog() {
  var q = (document.getElementById('audit-filter').value||'').toLowerCase();
  var filtered = q ? _auditRaw.filter(function(l){
    return (l.username||'').toLowerCase().includes(q) || (l.action||'').toLowerCase().includes(q) || (l.detail||'').toLowerCase().includes(q);
  }) : _auditRaw;
  renderAuditLog(filtered);
}

function renderAuditLog(logs) {
  var el = document.getElementById('audit-list');
  if (!logs.length) { el.innerHTML = '<div class="empty-state">Không có bản ghi nào</div>'; return; }
  el.innerHTML = logs.map(function(l){
    var dt = new Date(l.ts);
    var ts = dt.toLocaleDateString('vi-VN')+' '+dt.toLocaleTimeString('vi-VN',{hour12:false});
    var isFail = l.success === false;
    var act = (l.action || '?').toUpperCase();
    var actDisplay = act.length > 22 ? act.slice(0, 21) + '…' : act;
    var actLow = act.toLowerCase();
    var badgeCls = isFail ? 'log-badge-fail' : (actLow.includes('login') ? 'log-badge-ok' : 'log-badge-neutral');
    return '<div class="log-row">'
      +'<div class="log-badge-wrap"><span class="log-badge '+badgeCls+'" title="'+esc(act)+'">'+esc(actDisplay)+'</span></div>'
      +'<div class="log-user">'+esc(l.username||'—')+'</div>'
      +'<div class="log-ip">'+esc(l.ip||'—')+'</div>'
      +'<div class="log-detail">'+esc(l.detail||'—')+'</div>'
      +'<div class="log-ts">'+esc(ts)+'</div>'
    +'</div>';
  }).join('');
}

function purgeAuditLog() {
  var days = (document.getElementById('audit-total-info').textContent.match(/\((\d+) ngày\)/) || [])[1] || 30;
  if (!confirm('Xác nhận xóa tất cả audit log cũ hơn ' + days + ' ngày?\n\nHành động này không thể hoàn tác.')) return;
  fetch('/api/audit-log/purge',{method:'POST'})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.error){toast('Lỗi: '+d.error,'err');return;}
      toast('✓ Đã purge '+d.purged+' bản ghi cũ (còn '+d.kept+')','ok');
      loadAuditLog();
    })
    .catch(function(e){toast('Lỗi: '+e.message,'err');});
}

