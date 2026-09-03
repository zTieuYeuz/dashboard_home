/* ═══════════════════════════════════════════════════════════════════════════
   permissions-registry.js — NGUỒN KHAI BÁO QUYỀN DUY NHẤT (2026-07-27)
   ───────────────────────────────────────────────────────────────────────────
   VÌ SAO CÓ FILE NÀY
   Trước đây mỗi service phải khai báo lặp lại ở 6 NƠI rời rạc (ALL_SERVICES,
   _PAGE_PERM, menu _ALL, SERVICE_*_PAGES, DELEGATE_*, ALL_SERVICES_DEF).
   Quên 1 nơi là hỏng, mà KHÔNG có thông báo lỗi — bug thật đã gặp: thiếu
   'console-serial' trong ALL_SERVICES nên admin cấp quyền xong, server lặng lẽ
   xoá, user vẫn bị chặn. Giờ khai báo Ở ĐÂY MỘT LẦN, các danh sách kia được
   SINH RA tự động bên dưới.

   ───────────────────────────────────────────────────────────────────────────
   CÁCH THÊM 1 SERVICE MỚI  (bố cục anh Thoại chốt 2026-07-27)

     { section:'home',                      // 'home' | 'movi'
       id:'trang-a',                        // = key quyền trong KV
       name:'Trang A', icon:'🅰️',
       page:'/service-home/trang-a.html',   // để gác server + link menu
       access:'toggle',                     // Truy cập / Không truy cập
       features:[                           // dịch vụ con BÊN TRONG trang
         { id:'trang-a-report', name:'Xem báo cáo', icon:'📊' },
         { id:'trang-a-export', name:'Xuất dữ liệu', icon:'📤' },
       ] }

   Ý nghĩa đúng như anh mô tả:
     • Trang A có 2 lựa chọn: "Truy cập" / "Không truy cập".
     • Được "Truy cập" → user vào được trang.
     • Bên trong hiện danh sách dịch vụ con — tick cái nào user mới thấy cái đó.

   THÊM XONG LÀ CHẠY: không phải sửa ALL_SERVICES, _PAGE_PERM, menu hay editor
   quyền nữa. Chỉ còn 1 việc thủ công là card ngoài trang chủ (index.html) nếu
   muốn service hiện ở đó.

   ───────────────────────────────────────────────────────────────────────────
   AN NINH — LUÔN CHẶN Ở SERVER (nguyên tắc bắt buộc, anh Thoại nhắc lại)
   Ẩn menu/card chỉ là cho gọn giao diện, KHÔNG phải bảo mật. Mọi quyền phải
   chặn phía server:
     1. Trang HTML  → gác bằng `page` ở đây (worker.js đọc PAGE_PERM_MAP,
        không có quyền thì redirect về '/'), KHÔNG dựa vào việc giấu link.
     2. API         → mỗi handler tự gọi `hasPerm(env, session, '<key>')`
        (hoặc `hasWritePerm` cho thao tác ghi) TRƯỚC khi làm gì.
     3. Client-side → chỉ để hiển thị thân thiện; user sửa JS/gọi thẳng API
        vẫn phải bị server chặn.
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── Service Home ───────────────────────────────────────────────────────── */
const HOME = [
  { section: 'home', id: 'esxi', name: 'VMware ESXi', icon: '🖥', page: '/service-home/vmware-home.html', access: 'rw' },
  { section: 'home', id: 'n8n', name: 'n8n Automation', icon: '⚡', page: '/service-home/n8n.html', access: 'rw' },
  { section: 'home', id: 'casaos', name: 'CasaOS', icon: '🏠', page: '/service-home/casaos.html', access: 'rw' },
  /* /service-home/ssh.html là TRANG GỘP "Terminal Home", chứa 3 cụm: Termix
     (quyền 'ssh' — chính là service này) · Web Console Serial ('console-serial')
     · SSH Hiện trường ('ssh-field'). Cụm nào thiếu quyền thì tự mờ trong trang.

     Dùng pageKeys chứ KHÔNG dùng accessKeys: accessKeys nghĩa là trang cha không
     có quyền riêng (quyền nằm hết ở mục con) — khai vậy thì quyền 'ssh' biến mất
     khỏi Settings, không ai cấp quyền Termix được nữa. Đã dính đúng lỗi này.

     ⚠️ Đổi danh sách này thì sửa cho khớp CẢ 3 chỗ: _TERMK (worker.js, menu),
     _TERMINAL_KEYS (index.html, thẻ trang chính), CARDS (ssh.html, khoá từng cụm). */
  { section: 'home', id: 'ssh', name: 'SSH Terminal', icon: '⌨', page: '/service-home/ssh.html', access: 'toggle',
    pageKeys: ['ssh', 'console-serial', 'ssh-field', 'consolepi'] },
  /* ConsolePi — console server chạy sẵn, NHÚNG THẲNG bằng iframe (2026-08-31).
     Khác ba cụm trên ở chỗ: ba cụm kia là công cụ mình tự viết, cụm này là một
     trang web sẵn có của thiết bị, chỉ mượn khung để xem cho tiện.

     Nhúng được vì đã kiểm header thật: KHÔNG có X-Frame-Options, KHÔNG có
     frame-ancestors. Nếu sau này ConsolePi nâng cấp mà thêm hai header đó thì
     khung sẽ trắng — lúc ấy dùng nút "mở tab riêng" đã đặt sẵn trên thanh.

     Nó có ĐĂNG NHẬP RIÊNG (chuyển hướng /login), không qua Cloudflare Access,
     nên dashboard không thay nó đăng nhập được — người dùng tự nhập trong khung. */
  { section: 'home', id: 'consolepi', name: 'ConsolePi', icon: '🔌', page: '/service-home/consolepi.html', access: 'toggle' },
  /* Web Console (Serial) — cùng BỘ BA QUYỀN CON như SSH Hiện trường (2026-08-12,
     anh Thoại: "trợ lý console giống hệt trợ lý SSH hiện trường"). Ý nghĩa từng mức
     giống hệt bên kia, chỉ khác đường đi tới thiết bị là DÂY CONSOLE thay vì SSH —
     mà đi dây console còn nguy hiểm hơn: thường dùng lúc thiết bị đang hỏng/mới tinh,
     gõ sai là brick hoặc mất sạch cấu hình, không có đường mạng nào để cứu từ xa.
     Quyền 'console-serial' (mở trang) KHÔNG tự cho dùng AI — phải cấp thêm từng mức. */
  { section: 'home', id: 'console-serial', name: 'Web Console (Serial)', icon: '🔌', page: '/service-home/console-serial.html', access: 'toggle',
    features: [
      { id: 'console-serial-ai-ask',    name: 'AI · Ask (chỉ đọc, không chèn lệnh)' },
      { id: 'console-serial-ai-agent',  name: 'AI · Agent (chèn lệnh, phải xác nhận từng lệnh)' },
      { id: 'console-serial-ai-bypass', name: 'AI · ByPass (AI TỰ CHẠY lệnh — cấp rất hạn chế)' },
    ] },
  /* Terminal SSH nhúng cho lúc đi công trường — SSH thật chạy trên laptop qua
     cầu nối dash-ssh (_infra/dash-ssh), vì trình duyệt không mở được socket TCP.

     BA QUYỀN CON = ba mức trợ lý AI được phép làm gì với terminal. Tách riêng vì
     mức độ nguy hiểm khác hẳn nhau, không thể gộp thành một ô tích:
       ask    — chỉ đọc màn hình và trả lời. KHÔNG chèn được gì.
       agent  — chèn được lệnh, nhưng MỖI lệnh phải anh bấm Đồng ý.
       bypass — AI tự gõ và tự bấm Enter trên thiết bị thật của khách hàng.
     Quyền 'ssh-field' (mở trang) KHÔNG tự cho dùng AI: không cấp quyền con nào
     thì bảng chat vẫn mở được nhưng mọi chế độ đều khoá. Cố ý — người chỉ cần
     terminal thì không có lý do gì được kèm luôn quyền cho AI gõ lệnh. */
  { section: 'home', id: 'ssh-field', name: 'SSH Hiện trường', icon: '🧰', page: '/service-home/ssh-field.html', access: 'toggle',
    features: [
      { id: 'ssh-field-ai-ask',    name: 'AI · Ask (chỉ đọc, không chèn lệnh)' },
      { id: 'ssh-field-ai-agent',  name: 'AI · Agent (chèn lệnh, phải xác nhận từng lệnh)' },
      { id: 'ssh-field-ai-bypass', name: 'AI · ByPass (AI TỰ CHẠY lệnh — cấp rất hạn chế)' },
    ] },
  { section: 'home', id: 'rustdesk', name: 'RustDesk Remote', icon: '🖥', page: '/service-home/rustdesk.html', access: 'toggle-read' },
  { section: 'home', id: 'fortigate', name: 'FortiGate', icon: '🛡', page: '/service-home/fortigate.html', access: 'rw' },
  { section: 'home', id: 'asus', name: 'ASUS Router', icon: '📡', page: '/service-home/asus.html', access: 'rw' },

  /* Services Hub — trang cha + danh sách site con (tick site nào thấy site đó) */
  { section: 'home', id: 'services-hub', name: 'Services Hub (Internal)', icon: '🏠',
    page: '/service-home/services-embed.html', access: 'toggle',
    featureGroups: [
      { folder: 'Network', icon: '🌐', features: [
        { id: 'hub-fortigate', name: 'FortiGate', icon: '🛡️' },
        { id: 'hub-asus', name: 'Router Asus', icon: '📡' },
      ]},
      { folder: 'Server', icon: '🖥️', features: [
        { id: 'hub-esxi', name: 'VMware ESXi', icon: '💾' },
        { id: 'hub-nas', name: 'NAS', icon: '🗄️' },
        { id: 'hub-casaos', name: 'CasaOS', icon: '🏠' },
        { id: 'hub-kasm', name: 'Kasm', icon: '🖥️' },
      ]},
      { folder: 'Automation', icon: '⚡', features: [
        { id: 'hub-n8n', name: 'n8n', icon: '⚡' },
      ]},
      { folder: 'Lab', icon: '🧪', features: [
        { id: 'hub-pnetlab', name: 'Pnetlab-network', icon: '🧪' },
      ]},
      { folder: 'Monitor', icon: '📊', features: [
        { id: 'hub-frigate', name: 'Frigate NVR', icon: '📷' },
        { id: 'hub-camera-nvr', name: 'Camera NVR', icon: '📹' },
      ]},
    ]},

  /* Camera Home — trang cha + các tính năng con. Giữ UI chuyên biệt (có lưới
     chọn camera) nên đánh dấu customUI; phần khai báo KEY vẫn tập trung ở đây. */
  { section: 'home', id: 'camera-home', name: 'Camera Home', icon: '📷',
    page: '/service-home/camera-home.html', access: 'toggle', customUI: 'camera-home-group',
    accessKeys: ['camera', 'camera_playback', 'camera_download', 'app_camera', 'camera_autoopen'],
    features: [
      { id: 'camera', name: 'Quyền xem (chọn camera)', icon: '👁' },
      { id: 'camera_playback', name: 'Playback', icon: '⏪' },
      { id: 'camera_download', name: 'Tải video', icon: '⬇' },
      { id: 'app_camera', name: 'Mở thẳng camera khi login', icon: '🚀' },
      { id: 'camera_autoopen', name: 'Tự động mở tất cả camera', icon: '📺' },
    ]},
];

/* ── Service Movi ───────────────────────────────────────────────────────── */
const MOVI = [
  { section: 'movi', id: 'meraki', name: 'Meraki Network', icon: '🌐', page: '/service-movi/meraki.html', access: 'toggle',
    panels: [
      { id: 'meraki.clients', name: 'Clients đang kết nối + Thiết bị bị chặn' },
      { id: 'meraki.devices', name: 'Thiết bị Meraki (APs/Switches)' },
      { id: 'meraki.status', name: 'Device Status (Real-time)' },
      { id: 'meraki.events', name: 'Network Events' },
      { id: 'meraki.uplinks', name: 'WAN Uplinks' },
      { id: 'meraki.vlans', name: 'L3 Interface / SVI trên Switch' },
      { id: 'meraki.ports', name: 'Switch Ports' },
    ]},
  { section: 'movi', id: 'topology', name: 'Network Topology (Movi Map)', icon: '🗺', page: '/service-movi/topology.html', access: 'toggle',
    panels: [
      { id: 'topology.topo', name: 'Sơ đồ Topology' },
      { id: 'topology.route', name: 'Route Map' },
      { id: 'topology.wiring', name: 'Sơ đồ dây switch (Wiring)' },
    ]},
  { section: 'movi', id: 'fortigate-movi', name: 'FortiGate Movi', icon: '🔥', page: '/service-movi/fortigate-movi.html', access: 'toggle',
    panels: [
      { id: 'fortigate-movi.interfaces', name: 'Interfaces + Bandwidth (đang chạy/dừng)' },
      { id: 'fortigate-movi.sdwan', name: 'SD-WAN Members & Rules' },
      { id: 'fortigate-movi.vpn', name: 'VPN IPSec + SSL VPN' },
      { id: 'fortigate-movi.policy', name: 'Firewall Policy' },
      { id: 'fortigate-movi.route', name: 'Route Table' },
    ]},
  /* camClass phải giữ đúng chuỗi cũ 'movi-cam-cb' — CSS/JS chọn camera bám vào tên này. */
  { section: 'movi', id: 'camera-movi', name: 'Camera Movi', icon: '📷', page: '/service-movi/camera-movi.html', access: 'toggle', hasCameras: true, camClass: 'movi-cam-cb' },
  { section: 'movi', id: 'n8n-movi', name: 'n8n Movi Automation', icon: '⚡', page: '/service-movi/n8n-movi.html', access: 'rw',
    panels: [
      { id: 'n8n-movi.workflows', name: 'Danh sách Workflows' },
      { id: 'n8n-movi.executions', name: 'Execution History' },
    ]},
  { section: 'movi', id: 'vmware01-movi', name: 'VMware ESXi 01 (Movi)', icon: '🖥', page: '/service-movi/vmware01-movi.html', access: 'rw',
    panels: [
      { id: 'vmware01-movi.vms', name: 'Danh sách Virtual Machines' },
      { id: 'vmware01-movi.datastores', name: 'Datastores' },
      { id: 'vmware01-movi.hosts', name: 'Host System Info' },
    ]},
  { section: 'movi', id: 'vmware02-movi', name: 'VMware ESXi 02 (Movi)', icon: '🖥', page: '/service-movi/vmware02-movi.html', access: 'rw',
    panels: [
      { id: 'vmware02-movi.vms', name: 'Danh sách Virtual Machines' },
      { id: 'vmware02-movi.datastores', name: 'Datastores' },
      { id: 'vmware02-movi.hosts', name: 'Host System Info' },
    ]},
  { section: 'movi', id: 'ssh-movi', name: 'Termix Movi', icon: '⌨', page: '/service-movi/ssh-movi.html', access: 'toggle' },

  /* Tool Movi — trang gồm nhiều công cụ nhỏ, mỗi công cụ 1 quyền riêng.
     Trang mở được nếu có BẤT KỲ công cụ nào → accessKeys = danh sách con. */
  { section: 'movi', id: 'tool-movi', name: 'Tool Movi — Quản lý tài khoản & tài sản', icon: '🔧',
    page: '/service-movi/tool-movi.html', access: 'toggle', customUI: 'tool-group', virtualParent: true,
    /* labelName: tên ngắn dùng cho NHÃN quyền của từng công cụ ("Tool: Tạo User") */
    labelName: 'Tool',
    features: [
      { id: 'tool-movi-create-user', name: 'Tạo User Movi', icon: '👤', label: 'Tạo User' },
      { id: 'tool-movi-block-user', name: 'Block User Movi', icon: '🚫', label: 'Block User' },
      { id: 'tool-movi-delete-user', name: 'Xóa User Movi', icon: '🗑️', label: 'Xóa User' },
      { id: 'tool-movi-asset-search', name: 'Tra Cứu Tài Sản', icon: '🔍', label: 'Tra Cứu Tài Sản' },
      { id: 'tool-movi-check-email', name: 'Check Email Azure', icon: '📧', label: 'Check Email' },
      { id: 'tool-movi-azure-group', name: 'Azure AD Group', icon: '👥', label: 'Azure Group' },
      { id: 'tool-movi-fg-policy-lan', name: 'FG Policy LAN', icon: '🔒', label: 'FG Policy LAN' },
      { id: 'tool-movi-fg-policy-wifi', name: 'FG Policy WiFi', icon: '📶', label: 'FG Policy WiFi' },
    ]},
];

export const PERMISSION_REGISTRY = [...HOME, ...MOVI];

/* Key cũ không còn service nào đang dùng. CỐ Ý GIỮ trong ALL_SERVICES: user cũ
   có thể còn lưu các quyền này trong KV — bỏ ra khỏi whitelist sẽ khiến chúng bị
   xoá mất ở lần lưu kế tiếp. Không hiện trong editor quyền (không có `page`).
   `hub-openclaw`: OpenClaw đã gỡ khỏi Services Hub nhưng key vẫn còn trong danh
   sách nhãn + uỷ quyền của bản đang chạy → giữ y nguyên để không đổi hành vi. */
export const LEGACY_PERM_KEYS = ['nas', 'frigate', 'openclaw', 'kasm'];
export const LEGACY_LABELLED = [
  { id: 'hub-openclaw', name: 'Hub · OpenClaw', section: 'home' },
];

/* ── Bộ sinh: từ registry ra các danh sách mà phần còn lại của hệ thống dùng ─ */

/** Mọi key quyền của 1 service (chính nó + các dịch vụ con). */
function keysOf(svc) {
  const out = [];
  // Trang cha có key riêng, TRỪ khi nó chỉ là vỏ gom nhóm (tool-movi, camera-home)
  if (!svc.virtualParent && !svc.accessKeys) out.push(svc.id);
  if (svc.accessKeys) out.push(...svc.accessKeys);
  (svc.features || []).forEach(f => { if (!out.includes(f.id)) out.push(f.id); });
  (svc.featureGroups || []).forEach(g => g.features.forEach(f => { if (!out.includes(f.id)) out.push(f.id); }));
  return out;
}

/** Danh sách whitelist cho sanitizePermissions/sanitizePanels (thứ tự ổn định). */
export function buildAllServices() {
  const out = [];
  PERMISSION_REGISTRY.forEach(svc => keysOf(svc).forEach(k => { if (!out.includes(k)) out.push(k); }));
  LEGACY_PERM_KEYS.forEach(k => { if (!out.includes(k)) out.push(k); });
  LEGACY_LABELLED.forEach(l => { if (!out.includes(l.id)) out.push(l.id); });
  return out;
}

/** { '/duong-dan.html': 'key' | ['key1','key2'] } — dùng để gác trang ở server. */
export function buildPagePermMap() {
  const map = {};
  PERMISSION_REGISTRY.forEach(svc => {
    if (!svc.page) return;
    /* pageKeys ≠ accessKeys — đừng lẫn:
       • accessKeys = "trang cha KHÔNG có quyền riêng, quyền nằm ở các mục con"
         (camera-home, tool-movi). Dùng nhầm cho service có quyền riêng thì
         chính quyền đó biến mất khỏi Settings — đã dính lúc gộp trang terminal.
       • pageKeys  = "trang cha VẪN có quyền riêng, nhưng còn mở được bằng vài
         quyền khác nữa" (Terminal Home: quyền 'ssh' của mình + 'console-serial'
         + 'ssh-field' của hai công cụ nằm chung trang). */
    const keys = svc.pageKeys ? svc.pageKeys.slice()
      : svc.accessKeys ? svc.accessKeys.slice()
      : (svc.virtualParent ? (svc.features || []).map(f => f.id) : [svc.id]);
    map[svc.page] = keys.length === 1 ? keys[0] : keys;
  });
  return map;
}

/** Nhãn tiếng Việt cho mọi key — dùng trong editor quyền & màn uỷ quyền. */
export function buildPermLabels() {
  const out = {};
  PERMISSION_REGISTRY.forEach(svc => {
    if (!svc.virtualParent && !svc.accessKeys) out[svc.id] = svc.name;
    (svc.features || []).forEach(f => {
      out[f.id] = svc.accessKeys ? svc.name + ' · ' + f.name
                : svc.virtualParent ? (svc.labelName || svc.name) + ': ' + (f.label || f.name)
                : f.name;
    });
    (svc.featureGroups || []).forEach(g => g.features.forEach(f => { out[f.id] = 'Hub · ' + f.name; }));
  });
  LEGACY_LABELLED.forEach(l => { out[l.id] = l.name; });
  return out;
}

/** Key mà admin có thể uỷ quyền cho manager, tách theo khu vực. */
export function buildDelegateKeys(section) {
  const out = [];
  PERMISSION_REGISTRY.filter(s => s.section === section).forEach(svc => keysOf(svc).forEach(k => { if (!out.includes(k)) out.push(k); }));
  LEGACY_LABELLED.filter(l => l.section === section).forEach(l => { if (!out.includes(l.id)) out.push(l.id); });
  return out;
}
