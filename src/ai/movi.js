/* ═══════════════════════════════════════════════════════════════════
   AI × Service Movi — module riêng (dễ bảo trì, import vào reads/actions)
   -------------------------------------------------------------------
   1) MOVI_READS  : nguồn đọc network/hạ tầng Movi (Meraki + FortiGate Movi
                    + ESXi Movi) — mỗi handler TỰ kiểm quyền theo user.
   2) network_health: nguồn CHẨN ĐOÁN tổng hợp — gọi song song nhiều nguồn,
                    trả gói tóm tắt để AI trả lời "mạng đang có vấn đề gì?".
   3) FORMS engine: "tool cố định gửi n8n" — biểu mẫu định nghĩa sẵn (KV
                    ai_forms, có mẫu mặc định): AI thu thập đủ trường theo
                    QUY TẮC → dashboard validate server-side → mới POST tới
                    webhook n8n. Sai/thiếu là từ chối, không gửi bậy.
   ═══════════════════════════════════════════════════════════════════ */
import { json, getSession, logActivity, isAdminUser, computeEffectivePermissions, cleanEnv, moviN8nAuth } from '../core.js';
import {
  handleMerakiDeviceStatus, handleMerakiSwitchPorts, handleMerakiSwitchPortConfigs,
  handleMerakiLinkAggregations, handleMerakiL3Routing,
  handleMoviSdwan, handleMoviSdwanRules,
  handleMerakiUplinks, handleMerakiEvents, handleMerakiDevices,
} from '../meraki.js';
import {
  handleMoviInterfaces, handleMoviPolicy, handleMoviDhcp, handleMoviSslVpn,
  handleMoviVpn, handleMoviLicense, handleMoviSystem, handleMoviFirewallUsers,
  handleMoviFortiviewSource,
} from '../movi-fortigate.js';
import { handleMoviVmwareData } from '../home-services.js';
import { handleToolMoviCreateUser } from '../tool-movi.js';

/* ── 1) Nguồn đọc Movi mở rộng (handler tự-gate: meraki / fortigate-movi) ── */
export const MOVI_READS = [
  // — Meraki network sâu —
  { id: 'meraki_device_status', perm: 'meraki', label: 'Trạng thái thiết bị Meraki (real-time)', handler: handleMerakiDeviceStatus,
    desc: 'Trạng thái sống từng AP/Switch/Appliance: online/offline/alerting/dormant + public IP. Hỏi "thiết bị nào offline/alerting".' },
  { id: 'meraki_switch_ports', perm: 'meraki', label: 'Cổng switch Meraki', handler: handleMerakiSwitchPorts,
    desc: 'Từng switch: tổng cổng, cổng đang nối, cổng LỖI, switch chết (0 cổng nối). Hỏi "cổng nào lỗi/switch nào chết".' },
  { id: 'meraki_port_configs', perm: 'meraki', label: 'Cấu hình cổng switch (VLAN/mode)', handler: handleMerakiSwitchPortConfigs,
    desc: 'Cấu hình từng cổng: access/trunk, VLAN, tên. Hỏi "cổng X cắm VLAN nào".' },
  { id: 'meraki_link_agg', perm: 'meraki', label: 'Link Aggregation (LACP)', handler: handleMerakiLinkAggregations,
    desc: 'Các nhóm gộp cổng giữa switch (LACP): nhóm, thành viên. Dùng khi hỏi về uplink giữa switch/topology.' },
  { id: 'meraki_l3_routing', perm: 'meraki', label: 'Định tuyến L3 (SVI + static routes)', handler: handleMerakiL3Routing,
    desc: 'SVI/interface L3 trên switch + static routes. Hỏi "route đi đâu", "VLAN X gateway gì".' },
  { id: 'movi_sdwan', perm: 'fortigate-movi', label: 'SD-WAN (trạng thái đường truyền)', handler: handleMoviSdwan,
    desc: 'SD-WAN FortiGate Movi: các member WAN, độ trễ/packet loss, đường nào đang dùng.' },
  { id: 'movi_sdwan_rules', perm: 'fortigate-movi', label: 'SD-WAN rules', handler: handleMoviSdwanRules,
    desc: 'Luật chọn đường SD-WAN (traffic nào đi WAN nào).' },
  // — FortiGate Movi sâu —
  { id: 'movi_fortiview_top', perm: 'fortigate-movi', label: 'Top nguồn dùng băng thông (FortiView)', handler: handleMoviFortiviewSource,
    desc: 'MÁY NÀO ĐANG XÀI NHIỀU BĂNG THÔNG NHẤT: top source theo bytes/sessions. Câu "ai làm chậm mạng" đọc cái này.' },
  { id: 'movi_fg_interfaces', perm: 'fortigate-movi', label: 'Interfaces FortiGate Movi', handler: handleMoviInterfaces,
    desc: 'Cổng mạng FortiGate Movi: up/down, IP, tốc độ.' },
  { id: 'movi_fg_policy', perm: 'fortigate-movi', label: 'Firewall policies Movi', handler: handleMoviPolicy,
    desc: 'Danh sách luật firewall văn phòng: nguồn/đích/dịch vụ/allow-deny.' },
  { id: 'movi_fg_dhcp', perm: 'fortigate-movi', label: 'DHCP leases Movi', handler: handleMoviDhcp,
    desc: 'Máy đang thuê IP qua DHCP (IP, MAC, hostname). Hỏi "IP này là máy nào".' },
  { id: 'movi_fg_sslvpn', perm: 'fortigate-movi', label: 'SSL-VPN Movi', handler: handleMoviSslVpn,
    desc: 'Ai đang kết nối SSL-VPN vào văn phòng.' },
  { id: 'movi_fg_vpn', perm: 'fortigate-movi', label: 'IPsec VPN Movi', handler: handleMoviVpn,
    desc: 'Các tunnel VPN site-to-site: trạng thái up/down.' },
  { id: 'movi_fg_license', perm: 'fortigate-movi', label: 'License FortiGate Movi', handler: handleMoviLicense,
    desc: 'Tình trạng license/hết hạn của FortiGate văn phòng.' },
  { id: 'movi_fg_fw_users', perm: 'fortigate-movi', label: 'Firewall users Movi', handler: handleMoviFirewallUsers,
    desc: 'User đang xác thực trên firewall (captive/FSSO).' },
  // — ESXi Movi (qua bridge kiểm quyền esxi) —
  { id: 'movi_vmware1', perm: 'esxi', label: 'ESXi Movi host 1 (máy ảo)', homeHandler: (env) => handleMoviVmwareData(env, 1),
    desc: 'Host ESXi Movi số 1: máy ảo (tên, vmId, trạng thái). vmId dùng cho movi_vm_power host=1.' },
  { id: 'movi_vmware2', perm: 'esxi', label: 'ESXi Movi host 2 (máy ảo)', homeHandler: (env) => handleMoviVmwareData(env, 2),
    desc: 'Host ESXi Movi số 2: máy ảo (tên, vmId, trạng thái). vmId dùng cho movi_vm_power host=2.' },
  // — Chẩn đoán tổng hợp —
  { id: 'movi_network_health', perm: 'meraki', label: 'KHÁM SỨC KHOẺ mạng Movi (tổng hợp)', handler: handleMoviNetworkHealth,
    desc: 'Gói chẩn đoán 1 phát: uplinks down?, thiết bị offline/alerting, cổng lỗi, sự kiện gần đây, CPU/RAM firewall, top máy ngốn băng thông, SD-WAN. LUÔN đọc nguồn này TRƯỚC khi trả lời "mạng có vấn đề gì / mạng chậm".' },
];

/* ── 2) Chẩn đoán tổng hợp — gọi song song, mỗi phần fail riêng lẻ không hỏng cả gói ── */
async function _part(promise, pick) {
  try {
    const resp = await promise;
    if (!resp || resp.status >= 400) return { error: 'HTTP ' + (resp ? resp.status : '?') };
    const d = await resp.json();
    return pick ? pick(d) : d;
  } catch (e) { return { error: (e && e.message) || String(e) }; }
}
export async function handleMoviNetworkHealth(request, env) {
  // Quyền: handler con tự gate (meraki / fortigate-movi). Phần nào user thiếu
  // quyền sẽ ra {error} riêng phần đó — AI vẫn chẩn đoán được phần còn lại.
  const [uplinks, devStatus, ports, events, fgSystem, fortiview, sdwan] = await Promise.all([
    _part(handleMerakiUplinks(request, env), d => ({ totalActive: d.totalActive, totalDown: d.totalDown,
      down: (d.devices || []).flatMap(x => (x.uplinks || []).filter(u => u.status !== 'active').map(u => ({ device: x.name, iface: u.interface, status: u.status }))).slice(0, 10) })),
    _part(handleMerakiDeviceStatus(request, env), d => ({ total: d.total, online: d.online, offline: d.offline, alerting: d.alerting,
      problem: (d.statuses || []).filter(s => s.status !== 'online').map(s => ({ name: s.name, model: s.model, status: s.status })).slice(0, 15) })),
    _part(handleMerakiSwitchPorts(request, env), d => ({ totalSwitches: d.totalSwitches, totalPorts: d.totalPorts,
      connectedPorts: d.connectedPorts, errorPorts: d.errorPorts, deadSwitches: d.deadSwitches })),
    _part(handleMerakiEvents(request, env), d => {
      const list = d.events || d.rows || (Array.isArray(d) ? d : []);
      return { recent: (list || []).slice(0, 12) };
    }),
    _part(handleMoviSystem(request, env), d => ({ hostname: d.hostname, version: d.version, cpu: d.cpu, mem: d.mem ?? d.memory, sessions: d.sessions, uptime: d.uptime })),
    _part(handleMoviFortiviewSource(request, env), d => {
      const rows = d.rows || d.sources || (Array.isArray(d) ? d : []);
      return { topTalkers: (rows || []).slice(0, 10) };
    }),
    _part(handleMoviSdwan(request, env), d => d && d.members ? { members: (d.members || []).slice(0, 8) } : d),
  ]);
  return json({
    fetchedAt: new Date().toISOString(),
    uplinks, deviceStatus: devStatus, switchPorts: ports, recentEvents: events,
    fortigate: fgSystem, bandwidth: fortiview, sdwan,
    hint: 'Chẩn đoán theo thứ tự: uplinks.totalDown>0 → mất WAN; deviceStatus.offline/alerting → thiết bị chết; switchPorts.errorPorts/deadSwitches → lỗi vật lý; fortigate.cpu/mem cao → firewall quá tải; bandwidth.topTalkers → máy ngốn băng thông; recentEvents → manh mối thời điểm. Phần nào {error} = không đọc được (thiếu quyền/nguồn lỗi) — nói rõ với user.',
  });
}

/* ── 2b) TRANSFORM gom gọn cho AI ──
   Dữ liệu Meraki thô rất lớn (hàng chục–trăm client) → AI dễ đếm sai + bị cắt cụt.
   Các hàm dưới TỔNG HỢP sẵn (byAp/bySsid/counts) để AI đọc chính xác 1 phát. */

/* CLIENT theo AP + SSID. Trả về byAp = {"<tên AP>": số client} → trả lời trực tiếp
   "AP X có bao nhiêu client". Map serial/mac → tên AP bằng danh sách thiết bị. */
export async function summarizeMerakiClients(data, env, req) {
  const clients = (data && data.clients) || [];
  let apBySerial = {}, apByMac = {};
  try {
    const dresp = await handleMerakiDevices(req, env);
    if (dresp.status < 400) {
      const dd = await dresp.json();
      for (const d of (dd.devices || [])) {
        if (d.serial) apBySerial[String(d.serial).toLowerCase()] = d.name;
        if (d.mac)    apByMac[String(d.mac).toLowerCase()]       = d.name;
      }
    }
  } catch { /* thiếu quyền devices vẫn gom được theo recentDeviceName */ }

  const byAp = {}, bySsid = {};
  let online = 0, wired = 0, wireless = 0;
  const compact = [];
  for (const c of clients) {
    const isWired = c.recentDeviceConnection === 'Wired' || !c.ssid || c.ssid === 'Wired' || c.ssid === '—';
    const ap = c.recentDeviceName
      || (c.recentDeviceSerial && apBySerial[String(c.recentDeviceSerial).toLowerCase()])
      || (c.recentDeviceMac    && apByMac[String(c.recentDeviceMac).toLowerCase()])
      || (isWired ? '(Wired/Switch)' : '(không rõ AP)');
    const ssid = c.ssid || (isWired ? 'Wired' : '—');
    const on = c.status === 'Online';
    if (on) online++;
    if (isWired) wired++; else wireless++;
    byAp[ap]     = (byAp[ap]     || 0) + 1;
    bySsid[ssid] = (bySsid[ssid] || 0) + 1;
    if (compact.length < 400) compact.push({ name: c.name || c.description || c.mac, ip: c.ip || '', ap, ssid, online: on });
  }
  const sortDesc = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));
  return {
    _summary: `Tổng ${clients.length} client (online ${online}); wireless ${wireless}, wired ${wired}.`,
    total: clients.length, online, wireless, wired,
    byAp:   sortDesc(byAp),
    bySsid: sortDesc(bySsid),
    note: 'byAp = {"<tên AP>": số client đang nối AP đó}. Muốn biết AP nào có bao nhiêu client → đọc byAp[<tên AP>] (vd byAp["F2-02"]). Tên AP không phân biệt hoa/thường: user hỏi "f2-02" = key "F2-02". Nếu không thấy key khớp thì AP đó hiện KHÔNG có client. clients[] là danh sách gọn (tối đa 400).',
    clients: compact,
  };
}

/* THIẾT BỊ Meraki: gom theo loại + tách thiết bị không online. */
export function summarizeMerakiDevices(data) {
  const devices = (data && data.devices) || [];
  const byType = {}; const problem = []; let online = 0;
  for (const d of devices) {
    byType[d.productType || '?'] = (byType[d.productType || '?'] || 0) + 1;
    if (d.status === 'online' || d.firmwareOk) online++;
    else problem.push({ name: d.name, model: d.model, status: d.status });
  }
  return {
    _summary: `Tổng ${devices.length} thiết bị Meraki (online ${online}). Loại: ${Object.entries(byType).map(([k, v]) => k + '=' + v).join(', ')}.`,
    total: devices.length, online, byType, problem,
    devices: devices.slice(0, 200).map(d => ({ name: d.name, model: d.model, serial: d.serial, ip: d.lanIp, type: d.productType, status: d.status, firmware: d.firmware })),
  };
}

/* SỰ KIỆN mạng: cắt còn 40 dòng gần nhất (đủ để chẩn đoán, không phình). */
export function summarizeMerakiEvents(data) {
  const list = (data && (data.events || data.rows)) || (Array.isArray(data) ? data : []);
  return { total: (list || []).length, events: (list || []).slice(0, 40) };
}

/* ── 3) FORMS — tool cố định gửi n8n theo quy tắc ──
   KV `ai_forms` = mảng form; trống thì dùng DEFAULT_FORMS. Mỗi form:
   { id, label, desc, perm, adminOnly, webhookEnv (tên secret chứa URL n8n),
     fields: [{name,label,required,pattern,patternDesc,enum,example}],
     rules: 'quy tắc chữ cho AI đọc + đối chiếu trước khi gửi' } */
export const DEFAULT_FORMS = [
  {
    id: 'movi_create_user',
    label: 'Tạo user mới trong hệ thống Movi',
    desc: 'Thu thập thông tin nhân viên mới rồi tạo qua workflow n8n. Dùng CHUNG endpoint + quyền với trang Tool Movi (quyền tool-movi-create-user).',
    // Khớp đúng hệ phân quyền có sẵn của dashboard: user được cấp quyền
    // `tool-movi-create-user` là dùng được (không cần là admin).
    perm: 'tool-movi-create-user', adminOnly: false,
    builtinHandler: 'tool_movi_create_user',   // gọi handleToolMoviCreateUser (1 nguồn sự thật)
    fields: [
      { name: 'firstName',     label: 'Tên (First Name)',   required: true,  example: 'An' },
      { name: 'lastName',      label: 'Họ và tên đệm (Last Name)', required: true, example: 'Nguyễn Văn' },
      { name: 'email',         label: 'Email User Movi (email công ty sẽ cấp)', required: true, pattern: '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$', patternDesc: 'email hợp lệ' },
      { name: 'personalEmail', label: 'Email cá nhân',      required: true,  pattern: '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$', patternDesc: 'email cá nhân hợp lệ' },
      { name: 'group',         label: 'Phòng ban (Phòng Ban)', required: true, example: 'Kế toán / IT / Kho…' },
      { name: 'jobTitle',      label: 'Chức danh (JobTitle)', required: true },
      { name: 'department',    label: 'Department',         required: true },
      { name: 'office',        label: 'Văn phòng (Office)', required: true },
      { name: 'mobilePhone',   label: 'Điện thoại',         required: true, pattern: '^[0-9+ .-]{8,15}$', patternDesc: '8-15 chữ số' },
      { name: 'manager',       label: 'Quản lý (Manager)',  required: false },
      { name: 'company',       label: 'Công ty (Company)',  required: true },
    ],
    // ⭐ TẤT CẢ trường BẮT BUỘC, chỉ manager (Quản lý) là tuỳ chọn.
    // Trường có "enum" = dropdown → AI phải liệt kê lựa chọn cho user chọn (không gõ tự do).
    // (Anh Thoai điền danh sách enum cho group/office/company/department qua "Kho công cụ" hoặc gửi Claude.)
    rules: 'Hỏi user LẦN LƯỢT ĐỦ MỌI trường (đừng hỏi dồn quá 3 mục 1 lần). BẮT BUỘC TẤT CẢ trường, CHỈ manager (Quản lý) là tuỳ chọn. Trường nào có "enum" (danh sách lựa chọn) thì PHẢI liệt kê các lựa chọn đó cho user chọn, không để user gõ tự do. Xác nhận lại TOÀN BỘ thông tin với user trước khi gửi. Chỉ gửi khi user đồng ý.',
  },
];
export async function getForms(env) {
  try {
    const kv = await env.DASHBOARD_KV.get('ai_forms', 'json');
    if (Array.isArray(kv) && kv.length) return kv;
  } catch { /* fallthrough */ }
  return DEFAULT_FORMS;
}

/* GET /api/ai/forms — session-gated; trả spec form (không lộ URL webhook). */
export async function handleAiFormsList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const forms = await getForms(env);
  return json({
    forms: forms.map(f => ({ id: f.id, label: f.label, desc: f.desc, perm: f.perm || null,
      adminOnly: !!f.adminOnly, fields: f.fields || [], rules: f.rules || '' })),
    howto: 'Thu thập đủ field theo rules → in ```dash-action {"action":"form_submit","params":{"form":"<id>","data":{...}}}``` — dashboard hiện hộp xác nhận đầy đủ nội dung rồi mới gửi n8n.',
  });
}

/* Validate + gửi 1 form THAY MẶT user (gọi từ handleAiExec). Trả Response. */
export async function submitForm(env, session, params, ip) {
  const forms = await getForms(env);
  const form = forms.find(f => f.id === (params.form || '').toString());
  if (!form) return json({ ok: false, error: 'Biểu mẫu không tồn tại' }, 404);

  // Quyền theo form (AI làm thay user)
  const admin = await isAdminUser(env, session);
  if (!admin) {
    if (form.adminOnly) return json({ ok: false, denied: true, error: 'Biểu mẫu "' + form.label + '" chỉ dành cho admin.' }, 403);
    if (form.perm) {
      const eff = await computeEffectivePermissions(env, session.username);
      const lvl = (eff && eff.permissions && eff.permissions[form.perm]) || 'none';
      if (lvl === 'none') return json({ ok: false, denied: true, error: 'Bạn không có quyền ' + form.perm + ' để gửi biểu mẫu này.' }, 403);
    }
  }

  // Validate dữ liệu theo spec — thiếu/sai là TỪ CHỐI, không gửi bậy
  const data = (params.data && typeof params.data === 'object') ? params.data : {};
  const errors = [];
  const clean = {};
  for (const fld of (form.fields || [])) {
    let v = data[fld.name];
    v = (v === undefined || v === null) ? '' : String(v).trim();
    if (!v) { if (fld.required) errors.push('Thiếu "' + fld.label + '" (' + fld.name + ')'); continue; }
    if (fld.enum && fld.enum.indexOf(v) < 0) { errors.push('"' + fld.label + '" phải là một trong: ' + fld.enum.join(', ')); continue; }
    if (fld.pattern) {
      let re; try { re = new RegExp(fld.pattern); } catch { re = null; }
      if (re && !re.test(v)) { errors.push('"' + fld.label + '" sai định dạng — ' + (fld.patternDesc || fld.pattern)); continue; }
    }
    clean[fld.name] = v.slice(0, 500);
  }
  const known = new Set((form.fields || []).map(f => f.name));
  for (const k of Object.keys(data)) if (!known.has(k)) errors.push('Trường lạ không có trong biểu mẫu: ' + k);
  if (errors.length) {
    return json({ ok: false, invalid: true, errors,
      error: 'Dữ liệu chưa đạt quy tắc, KHÔNG gửi: ' + errors.join(' · ') }, 400);
  }

  // ── Nếu form dùng handler dashboard có sẵn → gọi thẳng (1 nguồn sự thật:
  //    cùng webhook + transform + logic với trang Tool Movi) ──
  if (form.builtinHandler === 'tool_movi_create_user') {
    const req = new Request('https://internal/ai-form', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(clean),
    });
    let resp;
    try { resp = await handleToolMoviCreateUser(req, env, session); }
    catch (e) { return json({ ok: false, error: 'Lỗi tạo user: ' + ((e && e.message) || e) }, 502); }
    const ok = resp.status < 400;
    let rd = null; try { rd = await resp.json(); } catch { /* non-json */ }
    await logActivity(env, { action: 'ai-form:' + form.id, username: session.username, ip: ip || '?', success: ok,
      detail: (form.label + ' ' + JSON.stringify(clean)).slice(0, 200) });
    if (!ok) return json({ ok: false, error: (rd && rd.error) || ('Lỗi ' + resp.status), result: rd }, 502);
    return json({ ok: true, form: form.id, label: form.label, result: rd, sent: clean });
  }

  // Gửi n8n (form tuỳ biến qua webhookEnv)
  const url = cleanEnv(env[form.webhookEnv] || '');
  if (!url) return json({ ok: false, error: 'Webhook cho biểu mẫu này chưa cấu hình (secret ' + form.webhookEnv + '). Báo admin.' }, 503);
  let auth; try { auth = moviN8nAuth(env); } catch (e) { return json({ ok: false, error: e.message }, 503); }
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Authorization': auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ form: form.id, submittedBy: session.username, submittedAt: new Date().toISOString(), data: clean }),
      signal: AbortSignal.timeout(30000),
    });
    const ok = resp.status < 400;
    let rd = null; try { rd = await resp.json(); } catch { /* non-json */ }
    await logActivity(env, { action: 'ai-form:' + form.id, username: session.username, ip: ip || '?', success: ok,
      detail: (form.label + ' ' + JSON.stringify(clean)).slice(0, 200) });
    if (!ok) return json({ ok: false, error: 'n8n trả lỗi ' + resp.status }, 502);
    return json({ ok: true, form: form.id, label: form.label, result: rd, sent: clean });
  } catch (e) {
    return json({ ok: false, error: 'Không gửi được tới n8n: ' + ((e && e.message) || e) }, 502);
  }
}

/* Admin quản lý forms: GET/PUT /api/admin/ai-forms (gate admin ở worker). */
export async function handleAdminAiForms(request, env) {
  if (request.method === 'GET') {
    const forms = await getForms(env);
    const usingDefault = !(await env.DASHBOARD_KV.get('ai_forms'));
    return json({ forms, usingDefault });
  }
  if (request.method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    if (!Array.isArray(b.forms)) return json({ error: 'forms phải là mảng' }, 400);
    for (const f of b.forms) {
      if (!f.id || !f.label) return json({ error: 'Mỗi form cần id, label' }, 400);
      if (!f.webhookEnv && !f.builtinHandler) return json({ error: 'form ' + f.id + ' cần webhookEnv hoặc builtinHandler' }, 400);
      if (!Array.isArray(f.fields)) return json({ error: 'form ' + f.id + ' thiếu fields[]' }, 400);
    }
    await env.DASHBOARD_KV.put('ai_forms', JSON.stringify(b.forms.slice(0, 50)));
    return json({ ok: true, count: b.forms.length });
  }
  return json({ error: 'Method not allowed' }, 405);
}
