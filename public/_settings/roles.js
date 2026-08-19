/* ══════════════════════════════════════════
   TAB 4: ROLE MANAGEMENT
   ══════════════════════════════════════════ */
function loadGroups() {
  fetch('/api/policy/groups',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      allGroups = d.groups || [];
      renderGroupSidebar();
    })
    .catch(function(){toast('Lỗi tải groups','err');});
}

function loadCameras() {
  fetch('/api/admin/cameras',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){allCameras = d.cameras || [];})
    .catch(function(){});
  fetch('/api/admin/cameras/movi',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){allCamerasMovi = d.cameras || [];})
    .catch(function(){});
}

function renderGroupSidebar() {
  var el = document.getElementById('group-sidebar');
  if (!allGroups.length) {
    el.innerHTML = '<div class="empty-state" style="padding:2rem 1rem">Chưa có nhóm nào.<br>Tạo nhóm đầu tiên!</div>';
    return;
  }
  el.innerHTML = allGroups.map(function(g){
    var sel = g.id === currentGroupId ? ' selected' : '';
    var pageCount = Object.keys(g.permissions||{}).filter(function(k){return g.permissions[k]&&g.permissions[k]!=='none';}).length;
    var userCount = allUsers.filter(function(u){ return (u.groups||[]).indexOf(g.id) >= 0; }).length;
    var rolePill = g.role === 'admin'
      ? '<span style="font-size:10px;padding:1px 7px;border-radius:10px;font-weight:700;background:color-mix(in oklch,var(--bad) 15%,transparent);color:var(--bad);border:1px solid color-mix(in oklch,var(--bad) 25%,transparent)">👑 admin</span>'
      : g.role === 'user'
        ? '<span style="font-size:10px;padding:1px 7px;border-radius:10px;font-weight:700;background:color-mix(in oklch,var(--ok) 12%,transparent);color:var(--ok);border:1px solid color-mix(in oklch,var(--ok) 22%,transparent)">👤 user</span>'
        : '';
    return '<div class="group-item'+sel+'" onclick="selectGroup(\''+esc(g.id)+'\')">'
      +'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
        +'<span class="group-item-name">'+esc(g.name)+'</span>'+rolePill
      +'</div>'
      +(g.description?'<div class="group-item-desc">'+esc(g.description)+'</div>':'')
      +'<div class="group-item-meta">'
        +'<span>📄 '+pageCount+' trang được cấp</span>'
        +'<span>👥 '+userCount+' thành viên</span>'
      +'</div>'
    +'</div>';
  }).join('');
  el.innerHTML += '<div style="display:flex;gap:6px;margin-top:8px">'
    +'<button class="btn btn-danger btn-sm" style="flex:1" id="grp-del-btn" onclick="confirmDeleteGroup()" style="display:none">🗑 Xóa nhóm</button>'
    +'</div>';
  updateGroupDelBtn();
}

function updateGroupDelBtn() {
  var btn = document.getElementById('grp-del-btn');
  // Admin: xóa mọi Role Group. Delegate: backend chỉ trả về group do CHÍNH họ tạo
  // (createdBy) → chọn được group nào là group đó của họ → cho xóa (backend kiểm lại createdBy).
  if (btn) btn.style.display = currentGroupId ? '' : 'none';
}

/* Toggle permission editor visibility when role radio changes */
function onGroupRoleChange(val) {
  var ed = document.getElementById('grp-perm-editor');
  if (ed) ed.style.display = (val === 'admin') ? 'none' : '';
}

function selectGroup(id) {
  currentGroupId = id;
  // Update sidebar selection
  document.querySelectorAll('.group-item').forEach(function(el){
    el.classList.toggle('selected', el.onclick && el.onclick.toString().indexOf("'"+id+"'")>=0);
  });
  // Re-render sidebar to apply selection
  renderGroupSidebar();
  // Show editor
  var group = allGroups.find(function(g){return g.id===id;});
  if (!group) return;
  renderGroupEditor(group);
}

function renderGroupEditor(group) {
  var el = document.getElementById('group-editor');
  el.innerHTML = '';

  // ── Title + Role badge ──
  var roleColor = group.role === 'admin' ? 'var(--bad)' : group.role === 'user' ? 'var(--ok)' : 'var(--muted)';
  var roleBadge = group.role
    ? '<span style="display:inline-block;font-size:11px;padding:2px 9px;border-radius:12px;font-weight:700;margin-left:8px;background:color-mix(in oklch,'+roleColor+' 15%,transparent);color:'+roleColor+';border:1px solid color-mix(in oklch,'+roleColor+' 30%,transparent)">role: '+esc(group.role)+'</span>'
    : '<span style="display:inline-block;font-size:11px;padding:2px 9px;border-radius:12px;font-weight:600;margin-left:8px;background:var(--surface-2);color:var(--muted);border:1px solid var(--border)">no role</span>';
  var title = document.createElement('div');
  title.innerHTML = '<div class="editor-title">🔐 <span style="color:var(--accent)">'+esc(group.name)+'</span>'+roleBadge+'</div>'
    +(group.description?'<div style="font-size:12px;color:var(--muted);margin-top:4px">'+esc(group.description)+'</div>':'');
  el.appendChild(title);

  // ── Role Assignment (top-level, prominent) ──
  var roleSection = document.createElement('div');
  roleSection.style.cssText = 'margin-top:14px;padding:14px 16px;border-radius:10px;background:color-mix(in oklch,var(--accent) 5%,transparent);border:1px solid color-mix(in oklch,var(--accent) 18%,transparent)';
  // Default to 'user' if group.role is null/undefined (no "no role" option anymore)
  var curRole = group.role || 'user';
  // In delegate mode: if group currently has admin role, show a warning but don't allow changing to admin
  var delegateModeAdminNote = (_delegateMode && group.role === 'admin')
    ? '<div style="font-size:11px;color:var(--bad);margin-top:6px;padding:6px 10px;border-radius:6px;background:color-mix(in oklch,var(--bad) 8%,transparent);border:1px solid color-mix(in oklch,var(--bad) 20%,transparent)">⚠️ Nhóm này hiện có role admin. Bạn không thể gán role admin, nhưng có thể chuyển về user.</div>'
    : '';
  roleSection.innerHTML = ''
    +'<div style="font-size:12px;font-weight:700;color:var(--text-2);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">🎭 Role của nhóm</div>'
    +'<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
      +'<label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;padding:6px 14px;border-radius:8px;border:1px solid color-mix(in oklch,var(--ok) 30%,transparent);background:color-mix(in oklch,var(--ok) 6%,transparent);color:var(--ok)">'
        +'<input type="radio" name="grp-role" value="user" '+(curRole==='user'?'checked':'')+' onchange="onGroupRoleChange(this.value)"/> 👤 user</label>'
      +(_delegateMode ? '' :
        '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;padding:6px 14px;border-radius:8px;border:1px solid color-mix(in oklch,var(--bad) 30%,transparent);background:color-mix(in oklch,var(--bad) 6%,transparent);color:var(--bad)">'
          +'<input type="radio" name="grp-role" value="admin" '+(curRole==='admin'?'checked':'')+' onchange="onGroupRoleChange(this.value)"/> 👑 admin (toàn quyền)</label>'
      )
    +'</div>'
    +(_delegateMode
      ? '<div style="font-size:11px;color:var(--muted);margin-top:7px">Bạn có thể gán role <strong>user</strong>. Gán role <strong>admin</strong> yêu cầu quyền Admin hệ thống.</div>'
      : '<div style="font-size:11px;color:var(--muted);margin-top:7px">Khi nhóm có role <strong>admin</strong> → tất cả thành viên có toàn quyền giống Admin, kể cả truy cập Settings. Mọi permission dưới đây sẽ bị ẩn vì không cần thiết.</div>'
    )
    +delegateModeAdminNote;
  el.appendChild(roleSection);

  // ── Permission editor (ẩn khi role = admin vì admin có full quyền rồi) ──
  var editorDiv = document.createElement('div');
  editorDiv.id = 'grp-perm-editor';
  editorDiv.style.marginTop = '14px';
  // Hide immediately if admin role is selected
  if (curRole === 'admin') editorDiv.style.display = 'none';
  el.appendChild(editorDiv);
  renderPermEditor('grp-perm-editor', group.permissions||{}, group.panels||{}, group.cameras||[], 'grp');
  // In delegate mode: hide permission rows that are not in managed services
  if (_delegateMode) {
    editorDiv.querySelectorAll('.perm-row').forEach(function(row) {
      var svcId = row.id.replace(/^grp-row-/, '');
      if (_delegateServices.indexOf(svcId) < 0) row.style.display = 'none';
    });
    // Hide entire service sections if all their rows are hidden
    editorDiv.querySelectorAll('.svc-section').forEach(function(sec) {
      var visibleRows = Array.prototype.slice.call(sec.querySelectorAll('.perm-row')).filter(function(r){return r.style.display!=='none';});
      if (!visibleRows.length) sec.style.display = 'none';
    });
    // Add a delegate mode notice
    var note = document.createElement('div');
    note.style.cssText = 'font-size:11px;color:var(--muted);padding:8px 12px;border-radius:6px;background:color-mix(in oklch,var(--accent) 5%,transparent);border:1px solid color-mix(in oklch,var(--accent) 12%,transparent);margin-bottom:10px';
    note.textContent = '🔑 Chỉ hiển thị các dịch vụ bạn được ủy quyền quản lý.';
    editorDiv.insertBefore(note, editorDiv.firstChild);
  }

  // ── Save button ──
  var saveRow = document.createElement('div');
  saveRow.style.cssText = 'display:flex;gap:8px;padding-top:12px;border-top:1px solid var(--border-soft)';
  saveRow.innerHTML = '<button class="btn btn-primary" onclick="saveGroupPerms()">💾 Lưu nhóm</button>';
  el.appendChild(saveRow);

  // ── Group Members Section ──
  var membersSection = document.createElement('div');
  membersSection.style.cssText = 'margin-top:20px;padding-top:18px;border-top:2px solid var(--border)';
  membersSection.innerHTML = '<div style="font-size:13px;font-weight:700;margin-bottom:12px">👥 Thành viên nhóm: <span style="color:var(--accent)">'+esc(group.name)+'</span></div>';

  // Member list
  var memberListDiv = document.createElement('div');
  memberListDiv.id = 'grp-member-list';
  renderGroupMemberList(group.id, memberListDiv);
  membersSection.appendChild(memberListDiv);

  // Add member control
  var addRow = document.createElement('div');
  addRow.style.cssText = 'display:flex;gap:8px;margin-top:10px;align-items:center';
  var nonMembers = allUsers.filter(function(u){
    if (u.role === 'admin') return false;
    if ((u.groups||[]).indexOf(group.id) >= 0) return false;
    if (group.role) {
      var alreadyInRoleGroup = (u.groups||[]).some(function(gid){
        var g = allGroups.find(function(x){return x.id===gid;});
        return g && g.role;
      });
      if (alreadyInRoleGroup) return false;
    }
    return true;
  });
  var hiddenCount = group.role ? allUsers.filter(function(u){
    if (u.role === 'admin') return false;
    if ((u.groups||[]).indexOf(group.id) >= 0) return false;
    return (u.groups||[]).some(function(gid){
      var g = allGroups.find(function(x){return x.id===gid;});
      return g && g.role;
    });
  }).length : 0;
  if (nonMembers.length) {
    addRow.innerHTML = '<select class="inp" id="grp-add-select" style="flex:1;font-size:12px;padding:6px 8px">'
      +'<option value="">— Chọn user để thêm —</option>'
      +nonMembers.map(function(u){return '<option value="'+esc(u.username)+'">'+esc(u.username)+'</option>';}).join('')
      +'</select>'
      +'<button class="btn btn-primary btn-sm" onclick="addUserToGroup(\''+esc(group.id)+'\')">+ Thêm</button>'
      +(hiddenCount > 0 ? '<span style="font-size:11px;color:var(--muted);margin-left:4px">('+hiddenCount+' user đã có role khác)</span>' : '');
  } else {
    addRow.innerHTML = '<span style="font-size:12px;color:var(--muted)">'
      +(hiddenCount > 0 ? 'Không còn user phù hợp ('+hiddenCount+' user đã thuộc nhóm Role Management khác)' : 'Tất cả users đã trong nhóm này')
      +'</span>';
  }
  membersSection.appendChild(addRow);
  el.appendChild(membersSection);

  // ── Linked User Groups Section ──
  var ugSection = document.createElement('div');
  ugSection.style.cssText = 'margin-top:18px;padding-top:16px;border-top:1px solid var(--border-soft)';
  ugSection.innerHTML = '<div style="font-size:13px;font-weight:700;margin-bottom:10px">🗂 User Groups liên kết — mọi user trong nhóm này tự động được áp dụng quyền</div>';

  // Linked user groups list
  var linkedUGs = allUserGroups.filter(function(ug){ return (ug.roleGroups||[]).indexOf(group.id) >= 0; });
  var ugListDiv = document.createElement('div');
  ugListDiv.id = 'grp-ug-list';
  if (linkedUGs.length) {
    ugListDiv.innerHTML = '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">'
      +linkedUGs.map(function(ug){
        return '<span style="display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;background:color-mix(in oklch,var(--accent) 8%,transparent);border:1px solid color-mix(in oklch,var(--accent) 22%,transparent);border-radius:20px;color:var(--text)">'
          +'🗂 '+esc(ug.name)+' <span style="font-size:10px;color:var(--muted)">('+((ug.members||[]).length)+' users)</span>'
          +'<button onclick="unlinkUserGroupFromPolicyGroup(\''+esc(ug.id)+'\',\''+esc(group.id)+'\')" title="Gỡ liên kết" style="background:none;border:none;cursor:pointer;color:var(--muted);font-size:14px;line-height:1;padding:0 0 0 2px">×</button>'
        +'</span>';
      }).join('')
    +'</div>';
  } else {
    ugListDiv.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:4px 0 8px">Chưa có User Group nào được liên kết</div>';
  }
  ugSection.appendChild(ugListDiv);

  // Add user group control
  var notLinked = allUserGroups.filter(function(ug){ return (ug.roleGroups||[]).indexOf(group.id) < 0; });
  var ugAddRow = document.createElement('div');
  ugAddRow.style.cssText = 'display:flex;gap:8px;align-items:center';
  if (notLinked.length) {
    ugAddRow.innerHTML = '<select class="inp" id="grp-add-ug-select" style="flex:1;font-size:12px;padding:6px 8px">'
      +'<option value="">— Chọn User Group để liên kết —</option>'
      +notLinked.map(function(ug){ return '<option value="'+esc(ug.id)+'">'+esc(ug.name)+' ('+((ug.members||[]).length)+' users)</option>'; }).join('')
    +'</select>'
    +'<button class="btn btn-primary btn-sm" onclick="linkUserGroupToPolicyGroup(\''+esc(group.id)+'\')">+ Liên kết</button>';
  } else {
    ugAddRow.innerHTML = '<span style="font-size:12px;color:var(--muted)">Tất cả User Groups đã được liên kết</span>';
  }
  ugSection.appendChild(ugAddRow);
  el.appendChild(ugSection);
}

function renderGroupMemberList(groupId, container) {
  var members = allUsers.filter(function(u){ return (u.groups||[]).indexOf(groupId)>=0; });
  if (!members.length) {
    container.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:8px 0">Chưa có thành viên nào</div>';
    return;
  }
  container.innerHTML = '<div style="display:flex;flex-wrap:wrap;gap:6px">'
    +members.map(function(u){
      return '<span style="display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;background:color-mix(in oklch,var(--accent) 10%,transparent);border:1px solid color-mix(in oklch,var(--accent) 25%,transparent);border-radius:20px;color:var(--text)">'
        +'👤 '+esc(u.username)
        +'<button onclick="removeUserFromGroup(\''+esc(u.username)+'\',\''+esc(groupId)+'\')" title="Xóa khỏi nhóm" style="background:none;border:none;cursor:pointer;color:var(--muted);font-size:14px;line-height:1;padding:0 0 0 2px">×</button>'
      +'</span>';
    }).join('')
    +'</div>';
}

function addUserToGroup(groupId) {
  var sel = document.getElementById('grp-add-select');
  if (!sel || !sel.value) return;
  var username = sel.value;
  var u = allUsers.find(function(x){return x.username===username;});
  if (!u) return;
  // Validate: each user can only be in 1 Role Management group
  var targetGroup = allGroups.find(function(g){return g.id===groupId;});
  if (targetGroup && targetGroup.role) {
    var existingRoleGroup = (u.groups||[]).map(function(gid){
      return allGroups.find(function(g){return g.id===gid;});
    }).find(function(g){ return g && g.role; });
    if (existingRoleGroup) {
      toast('Không thể thêm: "'+username+'" đã thuộc nhóm "'+existingRoleGroup.name+'" có role. Mỗi user chỉ được join 1 nhóm Role Management!', 'err');
      return;
    }
  }
  var newGroups = (u.groups||[]).concat([groupId]).filter(function(v,i,a){return a.indexOf(v)===i;});
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/groups',{
    method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({groups:newGroups})
  }).then(function(r){return r.json();}).then(function(d){
    if(d.error){toast('Lỗi: '+d.error,'err');return;}
    // Update local state
    u.groups = newGroups;
    toast('Đã thêm '+username+' vào nhóm','ok');
    // Re-render editor
    var group = allGroups.find(function(g){return g.id===groupId;});
    if(group) renderGroupEditor(group);
  }).catch(function(e){toast('Lỗi: '+e.message,'err');});
}

function removeUserFromGroup(username, groupId) {
  var u = allUsers.find(function(x){return x.username===username;});
  if (!u) return;
  var newGroups = (u.groups||[]).filter(function(g){return g!==groupId;});
  fetch('/api/admin/users/'+encodeURIComponent(username)+'/groups',{
    method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({groups:newGroups})
  }).then(function(r){return r.json();}).then(function(d){
    if(d.error){toast('Lỗi: '+d.error,'err');return;}
    u.groups = newGroups;
    toast('Đã xóa '+username+' khỏi nhóm','ok');
    var group = allGroups.find(function(g){return g.id===groupId;});
    if(group) renderGroupEditor(group);
  }).catch(function(e){toast('Lỗi: '+e.message,'err');});
}

/* ── Link/unlink User Group from Policy Group ── */
function linkUserGroupToPolicyGroup(policyGroupId) {
  var sel = document.getElementById('grp-add-ug-select');
  if (!sel || !sel.value) return;
  var ugId = sel.value;
  var ug = allUserGroups.find(function(x){return x.id===ugId;});
  if (!ug) return;
  var newRoleGroups = (ug.roleGroups||[]).concat([policyGroupId]).filter(function(v,i,a){return a.indexOf(v)===i;});
  fetch('/api/admin/user-groups/'+encodeURIComponent(ugId), {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({roleGroups: newRoleGroups})
  }).then(function(r){return r.json();}).then(function(d){
    if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
    ug.roleGroups = newRoleGroups;
    toast('Đã liên kết "'+ug.name+'" với nhóm', 'ok');
    var group = allGroups.find(function(g){return g.id===policyGroupId;});
    if (group) renderGroupEditor(group);
  }).catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

function unlinkUserGroupFromPolicyGroup(ugId, policyGroupId) {
  var ug = allUserGroups.find(function(x){return x.id===ugId;});
  if (!ug) return;
  var newRoleGroups = (ug.roleGroups||[]).filter(function(g){return g!==policyGroupId;});
  fetch('/api/admin/user-groups/'+encodeURIComponent(ugId), {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({roleGroups: newRoleGroups})
  }).then(function(r){return r.json();}).then(function(d){
    if (d.error) { toast('Lỗi: '+d.error, 'err'); return; }
    ug.roleGroups = newRoleGroups;
    toast('Đã gỡ liên kết "'+ug.name+'"', 'ok');
    var group = allGroups.find(function(g){return g.id===policyGroupId;});
    if (group) renderGroupEditor(group);
  }).catch(function(e){ toast('Lỗi: '+e.message, 'err'); });
}

/* ── Generic permission editor renderer ── */
function renderPermEditor(containerId, permissions, panels, cameras, pfx) {
  var el = document.getElementById(containerId);
  el.innerHTML = '';

  // Service Home section
  el.appendChild(buildServiceSection(
    '🏠 Service Home — Hạ tầng nội bộ',
    SERVICE_HOME_PAGES,
    permissions, panels, cameras, pfx, 'home'
  ));

  // Service Movi section
  el.appendChild(buildServiceSection(
    '🎬 Service Movi — Văn phòng Movi',
    SERVICE_MOVI_PAGES,
    permissions, panels, cameras, pfx, 'movi'
  ));
}

function buildServiceSection(title, pages, permissions, panels, cameras, pfx, sectionId) {
  var section = document.createElement('div');
  section.className = 'svc-section';
  section.id = pfx+'-sec-'+sectionId;

  var head = document.createElement('div');
  head.className = 'svc-section-head';
  head.innerHTML = '<div class="svc-section-title">'+title+'</div><span class="chev">▼</span>';
  head.onclick = function(){ section.classList.toggle('collapsed'); };
  section.appendChild(head);

  var body = document.createElement('div');
  body.className = 'svc-section-body';

  pages.forEach(function(page) {
    // ── Group header (non-permission divider) ──
    if (page.type === 'group-header') {
      var ghRow = document.createElement('div');
      ghRow.className = 'perm-group-header';
      ghRow.innerHTML = '<span>'+page.icon+'</span><span>'+esc(page.name)+'</span>';
      body.appendChild(ghRow);
      return;
    }

    // ── Services Hub hierarchical group ──
    if (page.type === 'services-hub-group') {
      var hubHasAccess = (permissions['services-hub']||'none') !== 'none';

      // Main row
      var hubRow = document.createElement('div');
      hubRow.className = 'perm-row';
      hubRow.id = pfx+'-row-services-hub-group';
      var hubRadios = '<label class="perm-radio-label"><input type="radio" name="'+pfx+'-perm-services-hub" value="none"'+(hubHasAccess?'':' checked')+' onchange="onHubAccessChange(\''+pfx+'\')"> Không truy cập</label>'
        +'<label class="perm-radio-label"><input type="radio" name="'+pfx+'-perm-services-hub" value="read"'+(hubHasAccess?' checked':'')+' onchange="onHubAccessChange(\''+pfx+'\')"> Truy cập</label>';
      hubRow.innerHTML = '<span class="perm-row-icon">🏠</span><span class="perm-row-name">Services Hub (Internal)</span><div class="perm-radios">'+hubRadios+'</div>';
      body.appendChild(hubRow);

      // Sub-section — folder tree
      var hubSub = document.createElement('div');
      hubSub.className = 'cam-home-sub';
      hubSub.id = pfx+'-hub-sub';
      hubSub.style.display = hubHasAccess ? '' : 'none';

      SERVICES_HUB_TREE.forEach(function(folder) {
        var fhdr = document.createElement('div');
        fhdr.className = 'hub-folder-hdr';
        fhdr.innerHTML = folder.icon+' '+esc(folder.folder);
        hubSub.appendChild(fhdr);

        var sitesRow = document.createElement('div');
        sitesRow.className = 'hub-sites-row';
        folder.sites.forEach(function(site) {
          var checked = (permissions[site.perm]||'none') !== 'none';
          var lbl = document.createElement('label');
          lbl.className = 'cam-home-sub-label';
          lbl.innerHTML = '<input type="checkbox" class="hub-site-cb" data-perm="'+esc(site.perm)+'"'+(checked?' checked':'')+'> '+site.icon+' '+esc(site.name);
          sitesRow.appendChild(lbl);
        });
        hubSub.appendChild(sitesRow);
      });

      body.appendChild(hubSub);
      return;
    }

    // ── Camera Home hierarchical group ──
    if (page.type === 'camera-home-group') {
      var hasAccess = (permissions['camera']||'none')!=='none'||
                      (permissions['camera_playback']||'none')!=='none'||
                      (permissions['camera_download']||'none')!=='none'||
                      (permissions['app_camera']||'none')!=='none'||
                      (permissions['camera_autoopen']||'none')!=='none';

      // Main row
      var chgRow = document.createElement('div');
      chgRow.className = 'perm-row';
      chgRow.id = pfx+'-row-camera-home-group';
      var chgRadios = '<label class="perm-radio-label"><input type="radio" name="'+pfx+'-perm-camera-home-group" value="none"'+(hasAccess?'':' checked')+' onchange="onCamHomeChange(\''+pfx+'\')"> Không truy cập</label>'
        +'<label class="perm-radio-label"><input type="radio" name="'+pfx+'-perm-camera-home-group" value="access"'+(hasAccess?' checked':'')+' onchange="onCamHomeChange(\''+pfx+'\')"> Truy cập</label>';
      chgRow.innerHTML = '<span class="perm-row-icon">📷</span><span class="perm-row-name">Camera Home</span><div class="perm-radios">'+chgRadios+'</div>';
      body.appendChild(chgRow);

      // Sub-section
      var subSec = document.createElement('div');
      subSec.className = 'cam-home-sub';
      subSec.id = pfx+'-cam-home-sub';
      subSec.style.display = hasAccess ? '' : 'none';

      // 1. Quyền xem
      var viewChecked = (permissions['camera']||'none') !== 'none';
      var viewRow = document.createElement('div');
      viewRow.className = 'cam-home-sub-row';
      viewRow.innerHTML = '<label class="cam-home-sub-label"><input type="checkbox" id="'+pfx+'-camhome-view"'+(viewChecked?' checked':'')+' onchange="onCamHomeViewChange(\''+pfx+'\')"> 👁 Quyền xem (chọn camera)</label>';
      subSec.appendChild(viewRow);

      // Camera grid
      var camSec2 = document.createElement('div');
      camSec2.className = 'cam-grid';
      camSec2.id = pfx+'-cams-camera';
      camSec2.style.display = viewChecked ? '' : 'none';
      var _camCustomNames = {};
      try { _camCustomNames = JSON.parse(localStorage.getItem('cam_names_v1')||'{}'); } catch(e){}
      allCameras.forEach(function(cam){
        var checked2 = cameras.indexOf(cam.id) >= 0;
        var lbl2 = document.createElement('label');
        lbl2.className = 'cam-check-label';
        var dname = _camCustomNames[cam.id] || cam.name || cam.id;
        lbl2.innerHTML = '<input type="checkbox" class="home-cam-cb" value="'+esc(cam.id)+'"'+(checked2?' checked':'')+'>📷 '+esc(dname);
        camSec2.appendChild(lbl2);
      });
      if (!allCameras.length) { camSec2.innerHTML = '<span style="font-size:12px;color:var(--muted);padding:.25rem 0">Chưa có dữ liệu camera</span>'; }
      subSec.appendChild(camSec2);

      // 2. Quyền Playback
      var pbChecked = (permissions['camera_playback']||'none') !== 'none';
      var pbRow = document.createElement('div');
      pbRow.className = 'cam-home-sub-row';
      pbRow.innerHTML = '<label class="cam-home-sub-label"><input type="checkbox" id="'+pfx+'-camhome-playback"'+(pbChecked?' checked':'')+'>  📼 Quyền Playback (xem lại ghi hình)</label>';
      subSec.appendChild(pbRow);

      // 3. Quyền Tải video
      var dlChecked = (permissions['camera_download']||'none') !== 'none';
      var dlRow = document.createElement('div');
      dlRow.className = 'cam-home-sub-row';
      dlRow.innerHTML = '<label class="cam-home-sub-label"><input type="checkbox" id="'+pfx+'-camhome-download"'+(dlChecked?' checked':'')+'>  ⬇ Quyền Tải video</label>';
      subSec.appendChild(dlRow);

      // 4. App Camera — auto-redirect vào trang camera khi đăng nhập
      var appCamChecked = (permissions['app_camera']||'none') !== 'none';
      var appCamRow = document.createElement('div');
      appCamRow.className = 'cam-home-sub-row';
      appCamRow.innerHTML = '<label class="cam-home-sub-label"><input type="checkbox" id="'+pfx+'-camhome-app-camera"'+(appCamChecked?' checked':'')+'>  📲 Mở thẳng camera khi đăng nhập</label>';
      subSec.appendChild(appCamRow);

      // 5. Auto-open — tự động bật tất cả camera khi vào trang
      var autoOpenChecked = (permissions['camera_autoopen']||'none') !== 'none';
      var autoOpenRow = document.createElement('div');
      autoOpenRow.className = 'cam-home-sub-row';
      autoOpenRow.innerHTML = '<label class="cam-home-sub-label"><input type="checkbox" id="'+pfx+'-camhome-autoopen"'+(autoOpenChecked?' checked':'')+'>  ▶️ Tự động mở tất cả camera khi vào trang</label>';
      subSec.appendChild(autoOpenRow);

      body.appendChild(subSec);
      return;
    }

    // For tool-group: parent perm is computed from sub-tools (any tool = write → parent = write)
    var perm = page.tools
      ? (page.tools.some(function(t){return (permissions[t.id]||'none')!=='none';}) ? 'write' : 'none')
      : (permissions[page.id] || 'none');

    var permRow = document.createElement('div');
    permRow.className = 'perm-row' + (page.indent ? ' perm-indented' : '');
    permRow.id = pfx+'-row-'+page.id;

    var icon = '<span class="perm-row-icon">'+page.icon+'</span>';
    var name = '<span class="perm-row-name">'+esc(page.name)+'</span>';
    var radios = page.perms.map(function(p){
      var lbl = (page.permLabels && page.permLabels[p]) || PERM_LABELS[p] || p;
      var chk = (perm===p) ? ' checked' : '';
      return '<label class="perm-radio-label">'
        +'<input type="radio" name="'+pfx+'-perm-'+page.id+'" value="'+p+'"'+chk
        +' onchange="onPermChange(\''+pfx+'\',\''+page.id+'\')">'
        +lbl+'</label>';
    }).join('');

    permRow.innerHTML = icon+name+'<div class="perm-radios">'+radios+'</div>';
    body.appendChild(permRow);

    // Panels sub-section (for Movi pages with panels)
    if (page.panels) {
      var panelSec = document.createElement('div');
      panelSec.className = 'panels-section';
      panelSec.id = pfx+'-panels-'+page.id;
      panelSec.style.display = (perm !== 'none') ? '' : 'none';

      page.panels.forEach(function(panel) {
        var pv = panels[panel.id]; // 'read', 'write', true, false, undefined
        var isVisible = !!pv;
        var isWrite = (pv === 'write' || pv === true);

        var panelRow = document.createElement('div');
        panelRow.className = 'panel-row';

        var visChk = '<label class="panel-toggle">'
          +'<input type="checkbox" id="'+pfx+'-pvis-'+panel.id+'"'+(isVisible?' checked':'')
          +' onchange="onPanelVisChange(\''+pfx+'\',\''+panel.id+'\')">'
          +'<span>Hiển thị</span></label>';

        var rwDisabled = isVisible ? '' : ' disabled';
        var rwSection = '<div class="panel-rw'+(isVisible?'':' disabled')+'" id="'+pfx+'-prw-'+panel.id+'">'
          +'<label><input type="radio" name="'+pfx+'-prw-'+panel.id+'" value="read"'+((!isWrite&&isVisible)?' checked':'')+'>📖 Chỉ xem</label>'
          +'<label><input type="radio" name="'+pfx+'-prw-'+panel.id+'" value="write"'+(isWrite?' checked':'')+'>✏ Toàn quyền</label>'
          +'</div>';

        panelRow.innerHTML = '<span class="panel-row-name">'+esc(panel.name)+'</span>'+visChk+rwSection;
        panelSec.appendChild(panelRow);
      });

      body.appendChild(panelSec);
    }

    /* Quyền con dạng `features` — mỗi cái một ô tích đơn giản (bật/tắt), KHÁC panels
       (panels còn có thêm mức chỉ-xem/toàn-quyền). Dùng cho các mức trợ lý AI:
       ssh-field-ai-ask/agent/bypass, console-serial-ai-ask/agent/bypass.
       Trước đây phần này KHÔNG tồn tại → 6 quyền đó không cấp được qua giao diện. */
    if (page.features) {
      var featSec = document.createElement('div');
      featSec.className = 'panels-section';
      featSec.id = pfx+'-feats-'+page.id;
      featSec.style.display = (perm !== 'none') ? '' : 'none';

      page.features.forEach(function(f) {
        var on = (permissions[f.id] || 'none') !== 'none';
        var row = document.createElement('div');
        row.className = 'panel-row';
        row.innerHTML = '<span class="panel-row-name">'+esc(f.name)+'</span>'
          + '<label class="panel-toggle">'
          + '<input type="checkbox" class="'+pfx+'-feat-cb" data-perm="'+esc(f.id)+'"'+(on?' checked':'')+'>'
          + '<span>Cấp quyền</span></label>';
        featSec.appendChild(row);
      });

      body.appendChild(featSec);
    }

    // Camera section (for pages with cameras)
    if (page.hasCameras) {
      var camSec = document.createElement('div');
      camSec.className = 'cam-grid';
      camSec.id = pfx+'-cams-'+page.id;
      camSec.style.display = (perm !== 'none') ? '' : 'none';

      // Use separate lists: Movi section → allCamerasMovi (16 camera), Home section → allCameras
      var pageCams = (sectionId === 'movi') ? allCamerasMovi : allCameras;

      pageCams.forEach(function(cam){
        var checked = cameras.indexOf(cam.id) >= 0;
        var lbl = document.createElement('label');
        lbl.className = 'cam-check-label';
        lbl.innerHTML = '<input type="checkbox" class="'+page.camClass+'" value="'+esc(cam.id)+'"'+(checked?' checked':'')+'>'
          +'📷 '+esc(cam.name||cam.id);
        camSec.appendChild(lbl);
      });

      if (!pageCams.length) {
        camSec.innerHTML = '<span style="font-size:12px;color:var(--muted);padding:.5rem 0">Chưa có camera nào trong hệ thống</span>';
      }

      body.appendChild(camSec);
    }

    // ── Tool group sub-section ──
    if (page.tools) {
      var toolSec = document.createElement('div');
      toolSec.className = 'tool-group-sec';
      toolSec.id = pfx+'-tools-'+page.id;
      toolSec.style.display = (perm !== 'none') ? '' : 'none';

      page.tools.forEach(function(tool) {
        var isEnabled = (permissions[tool.id] || 'none') !== 'none';
        var lbl = document.createElement('label');
        lbl.className = 'tool-check-label';
        lbl.innerHTML = '<input type="checkbox" id="'+pfx+'-tool-'+tool.id+'"'+(isEnabled?' checked':'')+'>'
          +'<span>'+tool.icon+' '+esc(tool.name)+'</span>';
        toolSec.appendChild(lbl);
      });

      body.appendChild(toolSec);
    }
  });

  section.appendChild(body);
  return section;
}

function onPermChange(pfx, pageId) {
  var radio = document.querySelector('input[name="'+pfx+'-perm-'+pageId+'"]:checked');
  var perm = radio ? radio.value : 'none';

  // ── Tool-group: toggle sub-tools; clear all when parent = none, check all when write ──
  var toolSec = document.getElementById(pfx+'-tools-'+pageId);
  if (toolSec) {
    toolSec.style.display = (perm !== 'none') ? '' : 'none';
    if (perm === 'none') {
      // Uncheck all sub-tool checkboxes
      toolSec.querySelectorAll('input[type="checkbox"]').forEach(function(cb){ cb.checked = false; });
    } else {
      // Auto-check all sub-tool checkboxes when parent is set to write
      toolSec.querySelectorAll('input[type="checkbox"]').forEach(function(cb){ cb.checked = true; });
    }
    return; // tool-groups have no panels/cameras
  }

  // Show/hide panels section
  var panelSec = document.getElementById(pfx+'-panels-'+pageId);
  if (panelSec) panelSec.style.display = (perm !== 'none') ? '' : 'none';
  /* Quyền con `features` (các mức trợ lý AI): ẩn khi trang bị tắt, và BỎ TÍCH luôn —
     tắt trang mà vẫn giữ quyền AI thì lúc bật lại quyền tự sống dậy, admin không ngờ.
     KHÔNG tự tích khi bật trang (khác tool-group): mở được trang không có nghĩa là
     mặc nhiên được cho AI tự gõ lệnh vào thiết bị — phải admin chủ động cấp. */
  var featSec = document.getElementById(pfx+'-feats-'+pageId);
  if (featSec) {
    featSec.style.display = (perm !== 'none') ? '' : 'none';
    if (perm === 'none') featSec.querySelectorAll('input[type="checkbox"]').forEach(function(cb){ cb.checked = false; });
  }
  // Show/hide camera section
  var camSec = document.getElementById(pfx+'-cams-'+pageId);
  if (camSec) camSec.style.display = (perm !== 'none') ? '' : 'none';
}

function onPanelVisChange(pfx, panelId) {
  var chk = document.getElementById(pfx+'-pvis-'+panelId);
  var rw = document.getElementById(pfx+'-prw-'+panelId);
  if (!chk || !rw) return;
  if (chk.checked) {
    rw.classList.remove('disabled');
    // Default to read if nothing selected
    var selected = rw.querySelector('input:checked');
    if (!selected) { var first = rw.querySelector('input[value="read"]'); if(first) first.checked=true; }
  } else {
    rw.classList.add('disabled');
  }
}

function onCamHomeChange(pfx) {
  var radio = document.querySelector('input[name="'+pfx+'-perm-camera-home-group"]:checked');
  var sub = document.getElementById(pfx+'-cam-home-sub');
  if (sub) sub.style.display = (radio && radio.value !== 'none') ? '' : 'none';
}

function onHubAccessChange(pfx) {
  var radio = document.querySelector('input[name="'+pfx+'-perm-services-hub"]:checked');
  var sub = document.getElementById(pfx+'-hub-sub');
  if (sub) sub.style.display = (radio && radio.value !== 'none') ? '' : 'none';
}

var SERVICES_HUB_TREE = _REG
  ? ((_REG.services || []).find(function(s){ return s.featureGroups; }) || {featureGroups:[]}).featureGroups
      .map(function(g){ return { folder:g.folder, icon:g.icon,
        sites:g.features.map(function(f){ return { name:f.name, icon:f.icon, perm:f.id }; }) }; })
  : [
  { folder:'Network', icon:'🌐', sites:[
    { name:'FortiGate',   icon:'🛡️', perm:'hub-fortigate' },
    { name:'Router Asus', icon:'📡', perm:'hub-asus' },
  ]},
  { folder:'Server', icon:'🖥️', sites:[
    { name:'VMware ESXi', icon:'💾', perm:'hub-esxi' },
    { name:'NAS',         icon:'🗄️', perm:'hub-nas' },
    { name:'CasaOS',      icon:'🏠', perm:'hub-casaos' },
    { name:'Kasm',        icon:'🖥️', perm:'hub-kasm' },
  ]},
  { folder:'Automation', icon:'⚡', sites:[
    { name:'n8n', icon:'⚡', perm:'hub-n8n' },
  ]},
  { folder:'Lab', icon:'🧪', sites:[
    { name:'Pnetlab-network', icon:'🧪', perm:'hub-pnetlab' },
  ]},
  { folder:'Monitor', icon:'📊', sites:[
    { name:'Frigate NVR', icon:'📷', perm:'hub-frigate' },
    { name:'Camera NVR',  icon:'📹', perm:'hub-camera-nvr' },
  ]},
];

function onCamHomeViewChange(pfx) {
  var cb = document.getElementById(pfx+'-camhome-view');
  var camSec = document.getElementById(pfx+'-cams-camera');
  if (camSec) camSec.style.display = (cb && cb.checked) ? '' : 'none';
}

/* ── Collect permissions from the editor ──
   pfx = 'usr' for user editor, 'grp' for group editor.
   Camera queries are SCOPED to their own container (not document-wide) to prevent
   cross-contamination between user editor and group editor when both exist in the DOM.
   Adding a new service: just add it to SERVICE_HOME_PAGES or SERVICE_MOVI_PAGES —
   this function iterates both arrays dynamically, nothing else to change here.
── */
/* Thu quyền con dạng `features` (các mức trợ lý AI). Gọi cho CẢ hai khối Home và Movi
   để sau này thêm service Movi có features cũng chạy sẵn, khỏi phải nhớ sửa lại.

   ⚠️ PHẢI luôn ghi giá trị — kể cả khi trang bị tắt (ghi 'none'). Bỏ trống thì khoá đó
   biến mất khỏi object quyền gửi lên server, đúng cái đã làm 6 quyền AI bị xoá âm thầm
   mỗi lần admin bấm Lưu (bug phát hiện 2026-08-15). */
function collectFeatures(page, permissions, pfx) {
  if (!page.features) return;
  var tat = (permissions[page.id] || 'none') === 'none';
  page.features.forEach(function(f) {
    var cb = document.querySelector('.' + pfx + '-feat-cb[data-perm="' + f.id + '"]');
    permissions[f.id] = (!tat && cb && cb.checked) ? 'read' : 'none';
  });
}

function collectPermissions(pfx) {
  var permissions = {};
  var panels = {};
  var cameras = [];

  // Helper: collect cameras scoped to the specific cam-grid container
  function collectCamsFrom(containerId) {
    var c = document.getElementById(containerId);
    if (!c) return;
    c.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb){ cameras.push(cb.value); });
  }

  // Service Home
  SERVICE_HOME_PAGES.forEach(function(page){
    if (page.type === 'services-hub-group') {
      var hubR = document.querySelector('input[name="'+pfx+'-perm-services-hub"]:checked');
      permissions['services-hub'] = (hubR && hubR.value !== 'none') ? 'read' : 'none';
      var hubSub = document.getElementById(pfx+'-hub-sub');
      if (hubSub) {
        hubSub.querySelectorAll('.hub-site-cb').forEach(function(cb) {
          permissions[cb.dataset.perm] = cb.checked ? 'read' : 'none';
        });
      } else {
        // sub-section not rendered (hub=none) → clear all hub-site keys
        SERVICES_HUB_TREE.forEach(function(f){ f.sites.forEach(function(s){ permissions[s.perm]='none'; }); });
      }
      return;
    }
    if (page.type === 'camera-home-group') {
      var mainR = document.querySelector('input[name="'+pfx+'-perm-camera-home-group"]:checked');
      if (!mainR || mainR.value === 'none') {
        permissions['camera'] = 'none';
        permissions['camera_playback'] = 'none';
        permissions['camera_download'] = 'none';
        permissions['app_camera'] = 'none';
        permissions['camera_autoopen'] = 'none';
      } else {
        var viewCb = document.getElementById(pfx+'-camhome-view');
        permissions['camera'] = (viewCb && viewCb.checked) ? 'read' : 'none';
        if (permissions['camera'] !== 'none') { collectCamsFrom(pfx+'-cams-camera'); }
        var pbCb = document.getElementById(pfx+'-camhome-playback');
        permissions['camera_playback'] = (pbCb && pbCb.checked) ? 'read' : 'none';
        var dlCb = document.getElementById(pfx+'-camhome-download');
        permissions['camera_download'] = (dlCb && dlCb.checked) ? 'read' : 'none';
        var appCamCb = document.getElementById(pfx+'-camhome-app-camera');
        permissions['app_camera'] = (appCamCb && appCamCb.checked) ? 'read' : 'none';
        var autoOpenCb = document.getElementById(pfx+'-camhome-autoopen');
        permissions['camera_autoopen'] = (autoOpenCb && autoOpenCb.checked) ? 'read' : 'none';
      }
      return;
    }
    if (page.type === 'group-header') return;
    var radio = document.querySelector('input[name="'+pfx+'-perm-'+page.id+'"]:checked');
    permissions[page.id] = radio ? radio.value : 'none';
    collectFeatures(page, permissions, pfx);
    if (page.hasCameras && permissions[page.id] !== 'none') {
      collectCamsFrom(pfx+'-cams-'+page.id);
    }
  });

  // Service Movi
  SERVICE_MOVI_PAGES.forEach(function(page){
    if (page.type === 'group-header') return; // skip visual-only dividers
    // Tool-group: collect each sub-tool individually; skip virtual parent key
    if (page.type === 'tool-group' && page.tools) {
      page.tools.forEach(function(tool) {
        var cb = document.getElementById(pfx+'-tool-'+tool.id);
        permissions[tool.id] = (cb && cb.checked) ? 'write' : 'none';
      });
      return;
    }
    var radio = document.querySelector('input[name="'+pfx+'-perm-'+page.id+'"]:checked');
    permissions[page.id] = radio ? radio.value : 'none';
    collectFeatures(page, permissions, pfx);
    // Sub-panels (Meraki, Topology, FortiGate Movi…)
    if (page.panels && permissions[page.id] !== 'none') {
      page.panels.forEach(function(panel){
        var visChk = document.getElementById(pfx+'-pvis-'+panel.id);
        if (visChk && visChk.checked) {
          var rwRadio = document.querySelector('input[name="'+pfx+'-prw-'+panel.id+'"]:checked');
          panels[panel.id] = (rwRadio && rwRadio.value === 'write') ? 'write' : 'read';
        } else {
          panels[panel.id] = false;
        }
      });
    }
    // Cameras (scoped to container, not document-wide)
    if (page.hasCameras && permissions[page.id] !== 'none') {
      collectCamsFrom(pfx+'-cams-'+page.id);
    }
  });

  return {permissions: permissions, panels: panels, cameras: cameras};
}

/* ── Save group permissions + role ── */
function saveGroupPerms() {
  if (!currentGroupId) return;
  var gid = currentGroupId;
  var result = collectPermissions('grp');
  var saveBtn = document.querySelector('#group-editor .btn-primary');
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = '⏳ Đang lưu...'; }

  var payload;
  if (_delegateMode) {
    // Only send permissions for managed services; don't allow setting admin role
    var filteredPerms = {};
    _delegateServices.forEach(function(svc) {
      if (result.permissions[svc] !== undefined) filteredPerms[svc] = result.permissions[svc];
    });
    var roleRadioD = document.querySelector('input[name="grp-role"]:checked');
    var groupRoleD = roleRadioD ? roleRadioD.value : null;
    // Safety: never send 'admin' from delegate mode (though the radio is hidden)
    if (groupRoleD === 'admin') groupRoleD = null;
    payload = { role: groupRoleD || null, permissions: filteredPerms };
  } else {
    // Read role radio
    var roleRadio = document.querySelector('input[name="grp-role"]:checked');
    var groupRole = roleRadio ? roleRadio.value : null;  // '' → null (no role)
    payload = {
      role:        groupRole || null,
      permissions: result.permissions,
      panels:      result.panels,
      cameras:     result.cameras
    };
  }

  fetch('/api/policy/groups/'+encodeURIComponent(gid),{
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  }).then(function(r){return r.json();}).then(function(d){
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu nhóm'; }
    if (d.error) { toast('Lỗi: '+d.error,'err'); return; }
    var savedRole = payload.role;
    toast('✓ Đã lưu nhóm '+gid+(savedRole?' (role: '+savedRole+')':''),'ok');
    // Update local cache immediately
    var g = allGroups.find(function(x){return x.id===gid;});
    if (g) {
      g.role = payload.role;
      if (!_delegateMode) { g.permissions = result.permissions; g.panels = result.panels; g.cameras = result.cameras; }
      else { Object.assign(g.permissions || {}, payload.permissions); }
    }
    renderGroupSidebar();
    // Re-render editor to reflect saved state
    if (g) renderGroupEditor(g);
  }).catch(function(e){
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '💾 Lưu nhóm'; }
    toast('Lỗi: '+e.message,'err');
  });
}

/* ── Create/Delete Group ── */
function openCreateGroup() {
  document.getElementById('grp-modal-title').textContent = '+ Tạo Group Mới';
  document.getElementById('gm-name').value = '';
  document.getElementById('gm-desc').value = '';
  document.getElementById('gm-role').value = 'user';
  document.getElementById('grp-modal-err').classList.remove('show');
  // In delegate mode: hide admin role option
  var adminOpt = document.querySelector('#gm-role option[value="admin"]');
  if (adminOpt) adminOpt.style.display = _delegateMode ? 'none' : '';
  openModal('grp-modal');
  document.getElementById('gm-name').focus();
}

function saveGroup() {
  var errEl = document.getElementById('grp-modal-err');
  var name = document.getElementById('gm-name').value.trim();
  var desc = document.getElementById('gm-desc').value.trim();
  var role = document.getElementById('gm-role').value || null;
  if (!name) { errEl.textContent='Tên nhóm không được để trống'; errEl.classList.add('show'); return; }
  fetch('/api/policy/groups',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name: name, description: desc, role: role})
  }).then(function(r){return r.json();}).then(function(d){
    if(d.error){errEl.textContent=d.error;errEl.classList.add('show');return;}
    closeModal('grp-modal');
    toast('✓ Đã tạo nhóm "'+name+'"'+(role?' với role '+role:''),'ok');
    loadGroups();
  }).catch(function(e){errEl.textContent='Lỗi: '+e.message;errEl.classList.add('show');});
}

function confirmDeleteGroup() {
  if (!currentGroupId) return;
  var g = allGroups.find(function(x){return x.id===currentGroupId;});
  if (!g) return;
  document.getElementById('confirm-title').textContent = 'Xóa Policy Group';
  document.getElementById('confirm-body').innerHTML = 'Bạn có chắc muốn xóa nhóm <strong>'+esc(g.name)+'</strong>?<br>Các user thuộc nhóm này sẽ mất quyền tương ứng.';
  document.getElementById('confirm-ok-btn').onclick = function(){
    fetch('/api/policy/groups/'+encodeURIComponent(currentGroupId),{method:'DELETE'})
      .then(function(r){return r.json();}).then(function(d){
        closeModal('confirm-modal');
        if(d.error){toast('Lỗi: '+d.error,'err');return;}
        toast('✓ Đã xóa nhóm '+currentGroupId,'ok');
        currentGroupId=null;
        document.getElementById('group-editor').innerHTML='<div class="empty-state" style="padding:4rem 2rem"><div style="font-size:2rem;margin-bottom:10px">🔐</div><div>Chọn nhóm để chỉnh quyền</div></div>';
        loadGroups();
      });
  };
  openModal('confirm-modal');
}

/* ═══════════════════════════════════════════════════════════
   TAB 5: TÀI KHOẢN CỦA TÔI
   ═══════════════════════════════════════════════════════════ */
function changeMyPassword() {
  var pw  = document.getElementById('acc-pw').value;
  var pw2 = document.getElementById('acc-pw2').value;
  var errEl = document.getElementById('acc-pw-err');
  errEl.classList.remove('show');
  if (!pw) { errEl.textContent='Mật khẩu không được để trống'; errEl.classList.add('show'); return; }
  if (pw.length < 6) { errEl.textContent='Mật khẩu phải có ít nhất 6 ký tự'; errEl.classList.add('show'); return; }
  if (pw !== pw2) { errEl.textContent='Mật khẩu xác nhận không khớp'; errEl.classList.add('show'); return; }
  var payload = { password: pw };
  if (_mfaEnabled) {
    var mfaCode = (document.getElementById('acc-mfa-code').value || '').trim();
    if (!mfaCode) { errEl.textContent='Vui lòng nhập mã MFA để xác nhận'; errEl.classList.add('show'); return; }
    if (!/^\d{6}$/.test(mfaCode)) { errEl.textContent='Mã MFA phải có đúng 6 chữ số'; errEl.classList.add('show'); return; }
    payload.mfaCode = mfaCode;
  }
  fetch('/api/admin/users/'+encodeURIComponent(__USER__.username), {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  }).then(function(r){return r.json();}).then(function(d){
    if (d.error) { errEl.textContent=d.error; errEl.classList.add('show'); return; }
    document.getElementById('acc-pw').value='';
    document.getElementById('acc-pw2').value='';
    if (_mfaEnabled) document.getElementById('acc-mfa-code').value='';
    toast('✓ Đã đổi mật khẩu thành công','ok');
  }).catch(function(e){ errEl.textContent='Lỗi: '+e.message; errEl.classList.add('show'); });
}

/* ── Account Tab init — ẩn/hiện đổi mật khẩu theo loại tài khoản ── */
function initAccountTab() {
  var isSaml = !!(window.__USER__ && window.__USER__.isSaml);
  var notice    = document.getElementById('pw-saml-notice');
  var localForm = document.getElementById('pw-local-form');
  var panelDesc = document.getElementById('pw-panel-desc');
  if (isSaml) {
    // SAML: ẩn form, hiện notice
    if (notice)    notice.style.display    = 'block';
    if (localForm) localForm.style.display = 'none';
    if (panelDesc) panelDesc.textContent   = 'Quản lý bởi Microsoft 365';
  } else {
    // Local: ẩn notice, hiện form
    if (notice)    notice.style.display    = 'none';
    if (localForm) localForm.style.display = '';
    if (panelDesc) panelDesc.textContent   = 'Cập nhật mật khẩu đăng nhập của bạn';
  }
}

/* ── MFA Management ── */
var _mfaSecret = null;
var _mfaIsReset = false; // true = đổi mã, false = thiết lập lần đầu
var _mfaEnabled = false; // tracks whether current user has MFA on

function loadMfaStatus() {
  fetch('/api/auth/mfa/status')
    .then(function(r){ return r.json(); })
    .then(function(d) {
      var on     = d.enabled;
      _mfaEnabled = !!on;
      var isSaml = !!(window.__USER__ && window.__USER__.isSaml);

      // ── Panel description & info banner ──
      var panelDesc      = document.getElementById('mfa-panel-desc');
      var mandatoryBanner = document.getElementById('mfa-mandatory-banner');
      var optionalBanner  = document.getElementById('mfa-optional-banner');
      if (isSaml) {
        if (panelDesc)       panelDesc.textContent     = 'Tùy chọn — có thể bật hoặc tắt.';
        if (mandatoryBanner) mandatoryBanner.style.display = 'none';
        if (optionalBanner)  { optionalBanner.style.display = 'flex'; }
      } else {
        if (panelDesc)       panelDesc.textContent     = 'Bắt buộc — không thể tắt. Chỉ có thể đổi mã (reset secret).';
        if (mandatoryBanner) mandatoryBanner.style.display = '';
        if (optionalBanner)  optionalBanner.style.display  = 'none';
      }

      // ── Status badge ──
      var badge = document.getElementById('mfa-status-badge');
      if (badge) badge.innerHTML = on
        ? '<span class="chip chip-ok" style="font-size:12px;padding:3px 12px">✓ Đang bật</span>'
        : '<span class="chip chip-err" style="font-size:12px;padding:3px 12px">✗ Chưa thiết lập</span>';

      // ── Description text ──
      var desc = document.getElementById('mfa-desc');
      if (desc) desc.textContent = on
        ? 'Tài khoản đang được bảo vệ bởi xác thực hai bước. Để thay đổi thiết bị Authenticator, nhấn "Đổi mã MFA".'
        : isSaml
          ? 'Tài khoản chưa thiết lập MFA dashboard. Tài khoản Microsoft của bạn đã có bảo mật riêng — thêm MFA dashboard cho lớp bảo vệ thứ hai.'
          : '⚠️ Tài khoản chưa thiết lập MFA. Vui lòng thiết lập ngay.';

      // ── Buttons ──
      var btnEn  = document.getElementById('btn-enable-mfa');
      var btnRst = document.getElementById('btn-reset-mfa');
      var btnDis = document.getElementById('btn-disable-mfa');
      if (btnEn)  btnEn.style.display  = on ? 'none' : '';
      if (btnRst) btnRst.style.display = on ? ''     : 'none';
      // "Tắt MFA" chỉ hiện với SAML users khi MFA đang bật
      if (btnDis) btnDis.style.display = (on && isSaml) ? '' : 'none';

      // ── Show MFA confirm field in change-password form ──
      var mfaRow = document.getElementById('acc-mfa-row');
      if (mfaRow) mfaRow.style.display = on ? '' : 'none';
    })
    .catch(function(){});
}

function openDisableMfaModal() {
  var inp = document.getElementById('mfa-disable-code');
  var err = document.getElementById('mfa-disable-err');
  if (inp) inp.value = '';
  if (err) { err.textContent = ''; err.classList.remove('show'); }
  openModal('mfa-disable-modal');
  if (inp) setTimeout(function(){ inp.focus(); }, 150);
}

function confirmDisableMfa() {
  var code = (document.getElementById('mfa-disable-code').value || '').replace(/\D/g,'');
  var err  = document.getElementById('mfa-disable-err');
  err.classList.remove('show');
  if (!/^\d{6}$/.test(code)) {
    err.textContent = 'Mã OTP phải có đúng 6 chữ số';
    err.classList.add('show');
    return;
  }
  fetch('/api/auth/mfa/disable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: code })
  })
  .then(function(r){ return r.json(); })
  .then(function(d) {
    if (d.success) {
      closeModal('mfa-disable-modal');
      toast('✓ MFA đã được tắt.', 'ok');
      loadMfaStatus();
    } else {
      err.textContent = d.error || 'Không thể tắt MFA';
      err.classList.add('show');
    }
  })
  .catch(function(){ err.textContent = 'Lỗi kết nối'; err.classList.add('show'); });
}

/* ── Passkey Management (WebAuthn) — 2026-07-27 ────────────────────────────
   Vanilla JS, không thư viện — cùng phong cách với login.html. Base64url
   helper lặp lại ở đây thay vì file dùng chung vì settings.html/login.html
   không có cơ chế share JS module giữa 2 trang (đúng convention hiện có của
   toàn bộ _settings/*.js — mỗi file tự chứa, không import lẫn nhau). */
function _pkB64urlToBuf(s) {
  var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var bin = atob(b64), buf = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function _pkBufToB64url(buf) {
  var bin = ''; var bytes = new Uint8Array(buf);
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function loadPasskeys() {
  var list = document.getElementById('passkey-list');
  if (!list) return;
  // Passkey CHỈ hỗ trợ trên desktop — đã tự test thật trên iPhone Safari
  // 2026-07-27: cả Bitwarden lẫn iCloud Keychain đều lỗi NotAllowedError khi
  // ĐĂNG KÝ (không chỉ đăng nhập). Chặn luôn ở đây để không ai đăng ký hỏng
  // trên điện thoại rồi thắc mắc — xem giải thích đầy đủ ở login.html.
  if (!window.PublicKeyCredential || document.documentElement.dataset.mobile === '1') {
    list.innerHTML = '<div style="font-size:12.5px;color:var(--muted)">Passkey hiện chỉ hỗ trợ trên máy tính (desktop). Dùng trình duyệt trên PC/laptop để đăng ký.</div>';
    var addBtn = list.nextElementSibling; if (addBtn) addBtn.style.display = 'none';
    return;
  }
  fetch('/api/auth/webauthn/credentials')
    .then(function(r){ return r.json(); })
    .then(function(d) {
      var creds = d.credentials || [];
      if (!creds.length) { list.innerHTML = '<div style="font-size:12.5px;color:var(--muted)">Chưa đăng ký thiết bị nào.</div>'; return; }
      list.innerHTML = creds.map(function(c) {
        var d2 = new Date(c.createdAt);
        return '<div style="display:flex;align-items:center;justify-content:space-between;padding:9px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:8px">'
          + '<div><div style="font-size:13px;font-weight:600">🔑 ' + esc(c.deviceName) + '</div>'
          + '<div style="font-size:11.5px;color:var(--muted)">Thêm ngày ' + d2.toLocaleDateString('vi-VN') + '</div></div>'
          + '<button class="btn btn-danger" style="padding:5px 10px;font-size:12px" onclick="deletePasskey(\'' + c.id.replace(/'/g, "\\'") + '\')">Xoá</button>'
          + '</div>';
      }).join('');
    })
    .catch(function(){ list.innerHTML = '<div style="font-size:12.5px;color:var(--bad)">Không tải được danh sách.</div>'; });
}

function registerPasskey() {
  if (!window.PublicKeyCredential) { toast('Trình duyệt này không hỗ trợ Passkey', 'err'); return; }
  var deviceName = prompt('Đặt tên cho thiết bị này (vd: "Vân tay laptop", "FaceID iPhone"):', '');
  if (deviceName === null) return; // bấm Huỷ
  deviceName = deviceName.trim() || 'Thiết bị không tên';

  fetch('/api/auth/webauthn/register-options', { method: 'POST' })
    .then(function(r){ return r.json(); })
    .then(function(d) {
      if (d.error) throw new Error(d.error);
      var opts = d.options;
      opts.challenge = _pkB64urlToBuf(opts.challenge);
      opts.user.id = _pkB64urlToBuf(opts.user.id);
      if (opts.excludeCredentials) {
        opts.excludeCredentials = opts.excludeCredentials.map(function(c) { return Object.assign({}, c, { id: _pkB64urlToBuf(c.id) }); });
      }
      return navigator.credentials.create({ publicKey: opts });
    })
    .then(function(cred) {
      var response = {
        id: cred.id, rawId: _pkBufToB64url(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: _pkBufToB64url(cred.response.clientDataJSON),
          attestationObject: _pkBufToB64url(cred.response.attestationObject),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      };
      return fetch('/api/auth/webauthn/register-verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceName: deviceName, response: response }),
      }).then(function(r){ return r.json(); });
    })
    .then(function(d) {
      if (!d.success) throw new Error(d.error || 'Đăng ký thất bại');
      toast('✓ Đã thêm passkey "' + deviceName + '"', 'ok');
      loadPasskeys();
    })
    .catch(function(e) {
      if (e && e.name === 'NotAllowedError') return; // bấm Huỷ trên hộp thoại thiết bị — không phải lỗi
      toast('Lỗi: ' + (e && e.message || e), 'err');
    });
}

function deletePasskey(id) {
  if (!confirm('Xoá passkey này? Thiết bị đó sẽ không đăng nhập bằng vân tay/FaceID được nữa.')) return;
  fetch('/api/auth/webauthn/credentials/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(function(r){ return r.json(); })
    .then(function(d) {
      if (!d.success) throw new Error(d.error || 'Xoá thất bại');
      toast('✓ Đã xoá passkey', 'ok');
      loadPasskeys();
    })
    .catch(function(e){ toast('Lỗi: ' + (e && e.message || e), 'err'); });
}

function startMfaSetup(isReset) {
  _mfaIsReset = !!isReset;
  fetch('/api/auth/mfa/setup', { method: 'POST' })
    .then(function(r){ return r.json(); })
    .then(function(d) {
      _mfaSecret = d.secret;
      // Update modal title based on action
      var s1title = document.querySelector('#mfa-s1 .modal-title');
      if (s1title) s1title.textContent = isReset ? '🔄 Đổi mã MFA — Bước 1/2' : '📱 Thiết lập MFA — Bước 1/2';
      var s2title = document.querySelector('#mfa-s2 .modal-title');
      if (s2title) s2title.textContent = isReset ? '🔄 Đổi mã MFA — Bước 2/2' : '📱 Thiết lập MFA — Bước 2/2';
      var confirmBtn = document.querySelector('#mfa-s2 .btn-primary');
      if (confirmBtn) confirmBtn.textContent = isReset ? '✓ Xác nhận đổi mã' : '✓ Bật MFA';
      var qrImg = document.getElementById('mfa-qr-img');
      if (d.qrDataUrl) {
        qrImg.src = d.qrDataUrl;
      } else {
        qrImg.src = 'https://api.qrserver.com/v1/create-qr-code/?size=180x180&margin=0&data=' + encodeURIComponent(d.otpauth);
      }
      document.getElementById('mfa-secret-box').textContent = d.secret;
      document.getElementById('mfa-secret-box').onclick = function() {
        navigator.clipboard.writeText(d.secret)
          .then(function(){ toast('Đã copy secret key!', 'ok'); })
          .catch(function(){});
      };
      document.getElementById('mfa-s1').style.display = '';
      document.getElementById('mfa-s2').style.display = 'none';
      document.getElementById('mfa-setup-err').classList.remove('show');
      openModal('mfa-setup-modal');
    })
    .catch(function(e){ toast('Lỗi khởi tạo MFA: ' + e.message, 'err'); });
}

function goMfaStep2() {
  document.getElementById('mfa-s1').style.display = 'none';
  document.getElementById('mfa-s2').style.display = '';
  document.getElementById('mfa-setup-code').value = '';
  document.getElementById('mfa-setup-err').textContent = '';
  document.getElementById('mfa-setup-err').classList.remove('show');
  setTimeout(function(){ document.getElementById('mfa-setup-code').focus(); }, 60);
}

function backMfaStep1() {
  document.getElementById('mfa-s2').style.display = 'none';
  document.getElementById('mfa-s1').style.display = '';
}

function confirmEnableMfa() {
  var code = document.getElementById('mfa-setup-code').value.trim();
  var err  = document.getElementById('mfa-setup-err');
  if (!/^\d{6}$/.test(code)) { err.textContent='Mã OTP phải có đúng 6 chữ số'; err.classList.add('show'); return; }
  err.classList.remove('show');
  fetch('/api/auth/mfa/enable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret: _mfaSecret, code: code })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.success) {
      closeModal('mfa-setup-modal');
      toast(_mfaIsReset ? '✓ Đổi mã MFA thành công! Dùng mã mới từ lần đăng nhập tới.' : '✓ MFA đã được bật thành công!', 'ok');
      loadMfaStatus();
      if (d.recoveryCodes && d.recoveryCodes.length) showRecoveryCodes(d.recoveryCodes);
    } else {
      err.textContent = d.error || 'Mã OTP không đúng';
      err.classList.add('show');
      document.getElementById('mfa-setup-code').value = '';
      document.getElementById('mfa-setup-code').focus();
    }
  }).catch(function(e){ err.textContent='Lỗi: '+e.message; err.classList.add('show'); });
}

/* Hiển thị recovery codes MỘT LẦN sau khi bật MFA — copy / tải về */
function showRecoveryCodes(codes) {
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,.65);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:16px';
  var grid = codes.map(function(c){ return '<div style="font-family:var(--font-mono);font-size:15px;font-weight:600;letter-spacing:1px;padding:8px;background:var(--surface-2);border:1px solid var(--border);border-radius:6px;text-align:center">'+esc(c)+'</div>'; }).join('');
  var box = document.createElement('div');
  box.style.cssText = 'background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;max-width:420px;width:100%;box-shadow:0 20px 50px rgba(0,0,0,.5)';
  box.innerHTML =
    '<div style="font-size:30px;text-align:center;margin-bottom:8px">🔐</div>'
    + '<div style="font-size:16px;font-weight:700;text-align:center;margin-bottom:6px">Mã khôi phục MFA</div>'
    + '<div style="font-size:12px;color:var(--warn);line-height:1.6;margin-bottom:16px;text-align:center">⚠️ Lưu các mã này nơi an toàn. Mỗi mã dùng <b>1 lần</b> để đăng nhập khi mất điện thoại.<br>Sẽ <b>không hiển thị lại</b> sau khi đóng.</div>'
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:18px">'+grid+'</div>'
    + '<div style="display:flex;gap:10px;justify-content:center">'
    + '<button class="btn btn-outline btn-sm" id="rc-copy">📋 Copy</button>'
    + '<button class="btn btn-outline btn-sm" id="rc-dl">⬇ Tải .txt</button>'
    + '<button class="btn btn-primary btn-sm" id="rc-close">Đã lưu, đóng</button>'
    + '</div>';
  ov.appendChild(box); document.body.appendChild(ov);
  var txt = codes.join('\n');
  box.querySelector('#rc-copy').onclick = function(){ navigator.clipboard.writeText(txt).then(function(){ toast('✓ Đã copy mã khôi phục','ok'); }); };
  box.querySelector('#rc-dl').onclick = function(){ var b=new Blob([txt],{type:'text/plain'}); var u=URL.createObjectURL(b); var a=document.createElement('a'); a.href=u; a.download='mfa-recovery-codes.txt'; a.click(); URL.revokeObjectURL(u); };
  box.querySelector('#rc-close').onclick = function(){ ov.remove(); };
}

// MFA disable is not allowed — function removed

