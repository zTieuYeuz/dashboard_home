/* ═══════════════════════════════════════════════════════════════════════════
   ssh-field-kb.js — KHO KIẾN THỨC MẠNG cho trợ lý SSH Hiện trường
   ───────────────────────────────────────────────────────────────────────────
   VÌ SAO CÓ FILE NÀY (đọc trước khi sửa)

   Trước đây mỗi lần AI kết luận sai một chuyện (đọc nhầm cột Mode của
   "show interfaces trunk", tưởng FortiGate không có LAG…) thì lại nhét thêm một
   dòng cảnh báo vào lời nhắc hệ thống. Cách đó hỏng ở hai đầu:

     • Vá lỗ chỗ: sửa chuyện này xong lần sau nó sai chuyện khác, không bao giờ hết.
       Anh Thoại nói đúng: "kiểu này sao áp dụng vào network được".
     • Lời nhắc phình ra, mà lời nhắc bị gửi lại MỖI LƯỢT gọi — một câu hỏi có thể
       gọi tới 14 lượt, nên mỗi dòng thêm vào bị nhân lên 14 lần.

   Cách làm ở đây: dựng KIẾN THỨC NỀN có hệ thống, để AI TRA KHI CẦN qua công cụ
   kb_lookup. Lời nhắc chỉ mang MỤC LỤC (ngắn), nội dung nặng chỉ tải khi dùng tới.
   Thêm kiến thức = thêm một mục ở đây, KHÔNG đụng vào lời nhắc.

   NGUYÊN TẮC VIẾT MỖI MỤC:
     1. Nói LỆNH NÀO CHỨNG MINH ĐƯỢC ĐIỀU GÌ — và quan trọng hơn: KHÔNG chứng
        minh được điều gì. Gần như mọi kết luận sai đều bắt nguồn từ việc suy ra
        thứ mà output đó không hề nói.
     2. Kèm cách ĐỌC CỜ/CỘT cụ thể, vì đó là chỗ hay đọc nhầm nhất.
     3. Nói rõ dấu hiệu KHOẺ so với dấu hiệu HỎNG, để biết khi nào KHÔNG cần sửa.
     4. Có triệu chứng → nguyên nhân thường gặp, theo thứ tự hay gặp.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
'use strict';

var KB = {};

/* ══════════════════════════════════════════════════════════════════════════
   1. MÔ HÌNH MẠNG — khung tư duy để biết mình đang đứng ở đâu
   ══════════════════════════════════════════════════════════════════════════ */
KB['mo-hinh-mang'] = [
  '# MÔ HÌNH MẠNG & PHÂN TẦNG',
  '',
  '## Phân tầng OSI dùng để CHẨN ĐOÁN (đi từ dưới lên, đừng nhảy cóc)',
  'L1 vật lý  : cáp, SFP, cổng up/down, tốc độ/duplex, lỗi CRC → hỏng ở đây thì mọi thứ trên đều vô nghĩa',
  'L2 liên kết: VLAN, trunk, MAC table, STP, LACP → "cùng VLAN có thấy nhau không"',
  'L3 mạng    : IP/mask, ARP, route, ICMP → "khác VLAN có đi qua nhau không"',
  'L4 giao vận: TCP/UDP port, session, NAT, firewall policy → "cổng dịch vụ có thông không"',
  'L7 ứng dụng: DNS, HTTP, RTSP… → "dịch vụ có trả lời không"',
  'Quy tắc: mỗi tầng chỉ hoạt động được khi tầng dưới đã ổn. Ping được IP mà web không vào',
  '→ L1-L3 ổn, đi thẳng xuống L4/L7. Ngược lại ping không được thì đừng soi DNS làm gì.',
  '',
  '## Các kiểu topology hay gặp và ý nghĩa khi soi lỗi',
  '',
  '### Ba tầng cổ điển (access – distribution – core)',
  'Access: switch tầng/phòng, cắm máy người dùng, thường L2 thuần, có PoE cho camera/AP.',
  'Distribution: gom nhiều access, thường là nơi ĐẶT GATEWAY (SVI) cho các VLAN, chạy định tuyến.',
  'Core: chuyển mạch tốc độ cao giữa các distribution, ít policy, ưu tiên nhanh.',
  '→ Khi soi: xác định GATEWAY của VLAN nằm ở đâu. Máy cùng VLAN không thấy nhau = lỗi L2 ở access.',
  '  Khác VLAN không thấy nhau = lỗi L3 ở chỗ đặt gateway, KHÔNG phải ở access.',
  '',
  '### Collapsed core (phổ biến nhất ở doanh nghiệp vừa và nhỏ — nhiều khả năng là mạng của anh Thoại)',
  'Gộp distribution + core làm một, hoặc thậm chí: vài switch L2 + một firewall làm gateway cho tất cả VLAN.',
  'Firewall (FortiGate) vừa là gateway VLAN, vừa là NAT ra Internet, vừa là nơi đặt policy liên-VLAN.',
  '→ Hệ quả quan trọng: traffic GIỮA HAI VLAN phải đi lên firewall rồi vòng xuống ("router on a stick").',
  '  Đường trunk switch↔firewall vì thế gánh cả traffic nội bộ liên VLAN → là nút thắt cổ chai điển hình.',
  '  Nếu firewall bật IPS/AV cho luồng nội bộ thì CPU firewall thành nút thắt, không phải băng thông.',
  '',
  '### Spine-leaf: dùng trong trung tâm dữ liệu, mọi leaf cách nhau đúng 1 spine. Ít gặp ở văn phòng.',
  '### Hub-spoke: chi nhánh về trung tâm qua VPN/WAN. Lỗi hay nằm ở MTU và route hai chiều.',
  '',
  '## Ranh giới L2/L3 — câu hỏi PHẢI trả lời được trước khi chẩn đoán',
  '1. VLAN này gateway nằm ở thiết bị nào? (switch L3 hay firewall)',
  '2. Giữa hai điểm đang lỗi có đi qua ranh giới L3 nào không?',
  '3. Có firewall/ACL nào nằm trên đường đó không?',
  'Không trả lời được 3 câu này thì mọi lệnh chạy tiếp đều là mò.',
].join('\n');

/* ══════════════════════════════════════════════════════════════════════════
   2. NGUYÊN TẮC BẰNG CHỨNG — cái quan trọng nhất trong kho này
   ══════════════════════════════════════════════════════════════════════════ */
KB['bang-chung'] = [
  '# NGUYÊN TẮC BẰNG CHỨNG KHI KẾT LUẬN',
  '',
  '## Gốc rễ của mọi chẩn đoán sai: suy ra thứ mà output KHÔNG hề nói',
  'Mỗi lệnh chỉ chứng minh được đúng phạm vi của nó. Trước khi kết luận, tự hỏi:',
  '  "Dòng nào trong output nói ĐÚNG điều tôi đang khẳng định?"',
  'Không chỉ ra được thì đó là suy đoán, phải nói rõ là suy đoán, hoặc chạy thêm lệnh cho đúng chỗ.',
  '',
  '## Ba lỗi suy luận hay gặp nhất',
  '1. NHẦM CỘT: đọc một cột rồi gán cho nó ý nghĩa của cột khác',
  '   (ví dụ kinh điển: cột Mode của "show interfaces trunk" là DTP, không phải giao thức gộp cổng).',
  '2. VẮNG MẶT ≠ KHÔNG TỒN TẠI: lệnh không hiện thứ gì đó có thể vì lệnh đó KHÔNG BAO GIỜ hiện loại đó',
  '   (ví dụ: "get system interface physical" của FortiGate không hiện interface aggregate).',
  '   Trước khi kết luận "không có X", phải chắc lệnh vừa chạy CÓ KHẢ NĂNG hiện X.',
  '3. TỰ MÂU THUẪN: kết luận trái ngược với chính mình ở lượt trước mà không nhận ra.',
  '   Trước khi kết luận, đọc lại những gì đã thu thập trong hội thoại.',
  '',
  '## Khi nào ĐƯỢC đề xuất sửa cấu hình đang chạy',
  'CHỈ khi chứng minh được nó ĐANG HỎNG: cổng down, cờ trạng thái xấu, bộ đếm lỗi tăng,',
  'traffic không đi qua, log báo lỗi. "Có thể chưa tối ưu" KHÔNG đủ để đụng vào thứ đang gánh cả hệ thống.',
  'Rủi ro mất kết nối khi sửa trunk/LAG/route đang live lớn hơn nhiều so với cái lợi mơ hồ.',
  'TUYỆT ĐỐI không đề xuất hạ cấp (bỏ LAG còn 1 cáp, tắt dự phòng, tắt STP) như "phương án đơn giản".',
  '',
  '## Thứ tự ưu tiên bằng chứng (mạnh → yếu)',
  '1. Bộ đếm lỗi/drop tăng theo thời gian (chạy 2 lần cách nhau, so số) — mạnh nhất',
  '2. Trạng thái/cờ của cổng, kênh, neighbor (up/down, bundled/standalone)',
  '3. Bảng thật: MAC table, ARP, route table, session table',
  '4. Cấu hình (running-config) — chỉ nói ý ĐỊNH, không nói thực tế đang chạy ra sao',
  'Cấu hình đúng mà cổng vẫn down thì lỗi ở L1, đừng sửa cấu hình.',
].join('\n');

/* ══════════════════════════════════════════════════════════════════════════
   3. ĐỌC OUTPUT — bảng "lệnh này chứng minh gì / KHÔNG chứng minh gì"
   ══════════════════════════════════════════════════════════════════════════ */
KB['doc-output-cisco'] = [
  '# ĐỌC OUTPUT CISCO IOS / IOS-XE',
  '',
  '## show interfaces trunk',
  'CHỨNG MINH: cổng nào đang trunk, native VLAN, danh sách VLAN được phép, VLAN nào thực sự active.',
  'KHÔNG chứng minh: giao thức gộp cổng (LACP/PAgP/static).',
  'Cột Mode (on / desirable / auto / nonegotiate) là chế độ DTP — chuyện thương lượng TRUNK,',
  'hoàn toàn không liên quan tới EtherChannel. "Po1  on" KHÔNG có nghĩa là EtherChannel tĩnh.',
  'Đọc kỹ 3 dòng khác nhau, đừng lẫn:',
  '  "Vlans allowed on trunk"                       = cấu hình cho phép (có thể 1-4094)',
  '  "Vlans allowed and active in management domain" = VLAN THẬT SỰ tồn tại và đi qua',
  '  "Vlans in spanning tree forwarding state"       = VLAN thật sự đang chuyển gói (sau STP)',
  '→ Allowed 1-4094 mà active chỉ 5 VLAN thì trunk chỉ mang 5 VLAN đó. Không có "rác 4094 VLAN".',
  '',
  '## show etherchannel summary  ← ĐÂY mới là chỗ xem gộp cổng',
  'CHỨNG MINH: giao thức (cột Protocol: LACP / PAgP / "-" nghĩa là static), cổng thành viên và trạng thái.',
  'Cờ sau tên port-channel: S=Layer2, R=Layer3, U=in use, D=down, M=not in use minimum links not met.',
  'Cờ sau tên cổng thành viên: (P)=bundled trong kênh · (D)=down · (I)=standalone, KHÔNG gộp được',
  '  · (s)=suspended · (w)=waiting to be aggregated.',
  'KHOẺ  = Po1(SU) + mọi thành viên (P). Không cần sửa gì.',
  'HỎNG  = có (I) hoặc (s) → hai đầu lệch giao thức/cấu hình, hoặc cắm nhầm cổng.',
  '',
  '## show interfaces status / show interfaces <x>',
  'CHỨNG MINH: up/down, tốc độ, duplex, VLAN access, bộ đếm lỗi.',
  'Đáng ngờ: CRC/input errors tăng (cáp/SFP/nhiễu), late collision (duplex mismatch),',
  'output drops (nghẽn hoặc buffer nhỏ), interface resets.',
  'Chạy lệnh HAI LẦN cách nhau ~30s rồi so số — số tuyệt đối lớn có thể là rác tích luỹ từ năm ngoái.',
  '',
  '## show vlan brief · show mac address-table · show ip arp · show ip route',
  'vlan brief   : VLAN có tồn tại không, cổng nào thuộc VLAN nào (chỉ access port).',
  'mac table    : MAC học được ở cổng nào → chứng minh L2 thông tới đâu.',
  'ip arp       : IP ↔ MAC ở tầng 3 → thiếu ARP thường là chưa thông L2 hoặc khác subnet.',
  'ip route     : có đường đi TỚI đích không. Nhớ kiểm tra CHIỀU VỀ ở thiết bị bên kia.',
  '',
  '## show spanning-tree [vlan X]',
  'CHỨNG MINH: root bridge là ai, cổng nào forwarding/blocking, có TCN dồn dập không.',
  'Root nằm ở switch access thay vì core = topology sai, dễ gây đường đi lòng vòng.',
  '',
  '## show running-config interface <x>',
  'CHỨNG MINH: ý định cấu hình. KHÔNG chứng minh nó đang chạy đúng như ý định.',
  '',
  '## Bẫy chế độ: "do <lệnh>" chỉ cần khi đang ở config mode. Ở exec mode gõ "do" là thừa (vẫn chạy).',
  'Đang ở (config)# mà gõ lệnh show trần sẽ báo lỗi — nhìn dấu nhắc trước khi gõ.',
].join('\n');

KB['doc-output-fortigate'] = [
  '# ĐỌC OUTPUT FORTIGATE (FortiOS)',
  '',
  '## Nhóm lệnh và phạm vi — nhớ đúng cái nào hiện cái gì',
  'get system interface physical  : CHỈ cổng vật lý. KHÔNG hiện aggregate/VLAN/software-switch.',
  '  → Không thấy LAG ở đây KHÔNG chứng minh được là không có LAG.',
  'get system interface           : mọi interface logic (gồm aggregate, VLAN, ssw).',
  'show system interface          : cấu hình interface; lọc bằng "| grep -f aggregate" (-f = kèm ngữ cảnh).',
  'diagnose hardware deviceinfo nic <port> : thống kê phần cứng NIC, bộ đếm lỗi/drop mức driver.',
  'get system status              : model, phiên bản FortiOS, HA.',
  'get system performance status  : CPU, RAM, session, throughput — xem có nghẽn CPU không.',
  '',
  '## Aggregate (LAG) trên FortiGate',
  'type aggregate + member cổng vật lý. MẶC ĐỊNH chạy LACP active (lacp-mode active).',
  'Đổi sang tĩnh bằng "set lacp-mode static". Muốn biết chắc thì đọc lacp-mode trong cấu hình.',
  'Kiểm tra hoạt động: "diagnose netlink aggregate name <tên>" — xem cổng nào đang active trong bundle.',
  '',
  '## Đường đi gói tin trong FortiOS (thứ tự này quyết định cách soi lỗi)',
  'ingress → DoS policy → IP integrity → NAT (DNAT/VIP) → routing → policy lookup → UTM (AV/IPS/webfilter)',
  '→ SNAT → egress.',
  '→ Hệ quả: gói bị chặn ở policy thì KHÔNG bao giờ tới UTM. Session đã tạo rồi thì đổi policy',
  '  không tác động tới session cũ (phải "diagnose sys session clear" hoặc chờ hết hạn).',
  '',
  '## Soi thật sự gói tin đi đâu — hai lệnh mạnh nhất',
  'diagnose sniffer packet <interface> "<bộ lọc bpf>" 4 0 a   → xem gói có tới không, tới bằng cửa nào',
  'diagnose debug flow: chuỗi lệnh (filter addr → show function-name en → trace start) → cho biết',
  '  gói khớp policy số mấy, bị drop vì lý do gì. Đây là bằng chứng mạnh nhất về "vì sao bị chặn".',
  'Nhớ "diagnose debug disable" sau khi xong, để bật debug lâu là tốn CPU.',
  '',
  '## Hardware acceleration (NPU/ASIC) — quan trọng với luồng video, camera',
  'Traffic được offload xuống NPU thì gần như không tốn CPU. Bật UTM (AV/IPS/SSL inspection) sẽ',
  'ĐẨY TRAFFIC LÊN CPU (auto-asic-offload mất tác dụng) → đó là nguyên nhân nghẽn thường gặp',
  'khi camera/video đi qua firewall, chứ không phải thiếu băng thông.',
  'Kiểm: "diagnose sys session list" xem cờ npu, và "get system performance status" xem CPU.',
  '',
  '## Bẫy cú pháp',
  'FortiOS dùng "get"/"show"/"diagnose"/"execute", KHÔNG có "show ip route" kiểu Cisco.',
  'Bảng định tuyến: "get router info routing-table all". Chính sách: "show firewall policy".',
].join('\n');

KB['doc-output-aruba'] = [
  '# ĐỌC OUTPUT ARUBA / HPE',
  '',
  '## Phân biệt hai dòng sản phẩm — cú pháp KHÁC HẲN NHAU',
  'ArubaOS-Switch (ProCurve cũ): "show vlan", "show trunks", VLAN gán kiểu "vlan 10 tagged 1-4".',
  '  Gộp cổng gọi là trunk (dễ nhầm với trunk 802.1Q của Cisco!): "trunk 1-2 trk1 lacp".',
  '  ⚠️ Ở Aruba/HPE, chữ "trunk" nghĩa là GỘP CỔNG. Còn mang nhiều VLAN thì gọi là "tagged".',
  '  Đây là chỗ dễ nhầm chết người khi quen Cisco.',
  'Aruba CX (AOS-CX): cú pháp gần Cisco hơn: "show vlan", "show lacp interfaces", "interface lag 1".',
  '',
  '## Lệnh hay dùng',
  'show system / show version   : model, phiên bản, để biết đang là ArubaOS-Switch hay CX',
  'show interfaces brief        : trạng thái cổng, tốc độ/duplex',
  'show lacp / show trunks      : trạng thái gộp cổng',
  'show mac-address / show arp  : bảng L2/L3',
].join('\n');

KB['doc-output-linux'] = [
  '# ĐỌC OUTPUT LINUX (server, máy chủ dịch vụ)',
  '',
  'ip a / ip -s link     : IP, trạng thái cổng, bộ đếm lỗi (errors/dropped)',
  'ip r                  : bảng định tuyến; "ip r get <ip>" cho biết gói sẽ đi cửa nào',
  'ss -tlnp / ss -s      : cổng nào đang nghe, tiến trình nào, thống kê socket',
  'ping / traceroute -n  : thông tới đâu (nhớ ICMP có thể bị chặn dù dịch vụ vẫn chạy)',
  'nc -vz <ip> <port>    : kiểm cổng TCP — chính xác hơn ping khi soi dịch vụ',
  'tcpdump -ni <if> ...  : bằng chứng mạnh nhất, gói có tới máy không',
  'ethtool <if>          : tốc độ/duplex thật của card',
  'journalctl -u <svc> -n 50 --no-pager : nhật ký dịch vụ',
  'df -h / free -m / top -bn1 : đĩa đầy, hết RAM, tải cao — hay bị đổ oan cho mạng',
  '',
  '⚠️ Ping không được KHÔNG có nghĩa là mạng đứt: nhiều nơi chặn ICMP. Dùng nc/ss để kiểm cổng thật.',
].join('\n');

/* ══════════════════════════════════════════════════════════════════════════
   4. KIẾN THỨC THEO CHỦ ĐỀ
   ══════════════════════════════════════════════════════════════════════════ */
KB['gop-cong'] = [
  '# GỘP CỔNG (LAG / EtherChannel / Port-Channel / Trunk-Aruba)',
  '',
  '## Ba cách gộp',
  'LACP (802.3ad, chuẩn mở)  : hai đầu thương lượng với nhau. An toàn nhất — lệch cấu hình thì kênh',
  '  không lên, chứ không gây loop. Cisco: "channel-group X mode active|passive".',
  'PAgP (riêng Cisco)        : tương tự nhưng độc quyền. "mode desirable|auto".',
  'Static / mode on          : không thương lượng, ép gộp. Lệch cấu hình một đầu = LOOP hoặc mất gói.',
  '',
  '## Cặp cấu hình hợp lệ',
  'active + active = OK · active + passive = OK · passive + passive = KHÔNG lên (không ai mở lời)',
  'on + on = OK nhưng nguy hiểm · on + active = KHÔNG lên (một bên chờ thương lượng, bên kia câm)',
  '',
  '## Điều kiện để cổng vào được kênh (lệch một cái là bị đá ra, cờ (I) hoặc (s))',
  'cùng tốc độ · cùng duplex · cùng chế độ trunk/access · cùng danh sách VLAN · cùng native VLAN · cùng MTU',
  '',
  '## Băng thông gộp KHÔNG có nghĩa một luồng nhanh gấp đôi',
  'Gộp 2×1G không cho một phiên TCP đạt 2Gbps. Cơ chế cân bằng tải băm theo src/dst MAC/IP/port rồi',
  'CHỐT một luồng vào MỘT cổng vật lý. Một luồng lớn duy nhất vẫn chỉ 1Gbps.',
  '→ Gộp cổng có ích khi NHIỀU luồng (nhiều camera, nhiều người dùng), không phải khi một luồng lớn.',
  '→ Nếu tải lệch hẳn về một cổng: xem lại thuật toán băm (Cisco: "port-channel load-balance src-dst-ip").',
  '',
  '## Kiểm tra sức khoẻ (làm theo đúng thứ tự này)',
  '1. Cisco: "show etherchannel summary" → Protocol + cờ. Mọi thành viên (P) là khoẻ.',
  '2. FortiGate: "show system interface | grep -f aggregate" → member + lacp-mode.',
  '3. So hai đầu: số cổng có khớp không, giao thức có tương thích không (bảng cặp ở trên).',
  '4. Chỉ khi thấy (I)/(s)/(D) hoặc số cổng lệch mới kết luận là có vấn đề.',
].join('\n');

KB['vlan-trunk'] = [
  '# VLAN & TRUNK 802.1Q',
  '',
  '## Khái niệm cốt lõi',
  'Access port: thuộc đúng 1 VLAN, gói đi ra KHÔNG có tag.',
  'Trunk port : mang nhiều VLAN, gói có tag 802.1Q, TRỪ native VLAN (đi không tag).',
  'Native VLAN LỆCH giữa hai đầu = hai VLAN bị nối thẳng vào nhau → rò traffic, rất khó phát hiện.',
  'Luôn kiểm native VLAN ở CẢ HAI đầu trunk.',
  '',
  '## Điều kiện để hai máy cùng VLAN thấy nhau qua nhiều switch',
  '1. VLAN phải TỒN TẠI trên mọi switch trên đường đi (show vlan brief)',
  '2. VLAN phải nằm trong allowed list của MỌI trunk trên đường đi',
  '3. STP không được block đường đó cho VLAN đó',
  'Thiếu bất kỳ điều nào: máy cùng VLAN vẫn không thấy nhau dù cấu hình access port đúng.',
  '',
  '## Pruning (thu hẹp allowed VLAN)',
  'Lợi ích THẬT: chặn VLAN lạ lọt sang sau này, giảm phạm vi broadcast nếu VLAN đó có tồn tại,',
  'giảm số instance STP phải tính. Đây là VỆ SINH CẤU HÌNH và AN NINH.',
  'KHÔNG phải cách tăng băng thông: VLAN không tồn tại trên switch thì vốn dĩ đã không có traffic nào.',
  'Rủi ro khi sửa: gõ thiếu VLAN đang dùng = mất kết nối ngay, kể cả đường SSH đang ngồi.',
  'An toàn hơn: dùng "switchport trunk allowed vlan add/remove" thay vì gõ lại cả danh sách.',
  '',
  '## Router-on-a-stick / SVI',
  'Liên VLAN phải qua thiết bị L3. Ở mạng nhỏ thường là firewall → traffic nội bộ vòng lên firewall.',
  'Xem gateway của VLAN nằm đâu trước khi kết luận "hai VLAN không thông".',
].join('\n');

KB['stp'] = [
  '# SPANNING TREE (STP / RSTP / MSTP)',
  '',
  'Nhiệm vụ: chặn vòng lặp L2. Vòng lặp L2 = bão broadcast = sập toàn mạng trong vài giây,',
  'và KHÔNG tự khỏi. Đây là sự cố nghiêm trọng nhất ở tầng 2.',
  '',
  '## Dấu hiệu đang có loop',
  'CPU switch tăng vọt · đèn mọi cổng nháy đồng loạt · MAC table nhảy liên tục giữa các cổng',
  '(log "mac flapping") · mất gói khắp nơi · SSH vào switch giật/rớt.',
  '',
  '## Kiểm tra',
  '"show spanning-tree" → ai là root, cổng nào blocking. Root NÊN nằm ở core/distribution.',
  'Root nằm ở một switch access hoặc ở thiết bị lạ = có người cắm bừa, đường đi lòng vòng.',
  '"show spanning-tree detail | include ieee|occurr" → đếm số lần thay đổi topology (TCN).',
  'TCN dồn dập = có cổng lên xuống liên tục, thường do máy tính/AP cắm vào cổng chưa bật portfast.',
  '',
  '## Nguyên tắc an toàn',
  'Cổng nối máy người dùng: bật portfast + bpduguard. Cổng nối switch khác: KHÔNG bật portfast.',
  'TUYỆT ĐỐI không tắt STP để "cho nhanh" — đó là cách chắc chắn nhất để sập mạng về sau.',
].join('\n');

KB['dinh-tuyen'] = [
  '# ĐỊNH TUYẾN & KẾT NỐI L3',
  '',
  '## Quy tắc vàng: định tuyến phải THÔNG CẢ HAI CHIỀU',
  'Rất nhiều sự cố là một chiều: A có route tới B, B không có route về A.',
  'Gói đi tới nơi nhưng không về được → biểu hiện y hệt như "không thông", dễ soi nhầm phía A.',
  'LUÔN kiểm route ở CẢ HAI đầu.',
  '',
  '## Thứ tự chọn đường',
  '1. Prefix dài nhất thắng (longest match) — /32 thắng /24 thắng /0',
  '2. Cùng độ dài prefix: administrative distance nhỏ hơn thắng (connected 0 < static 1 < OSPF 110 < BGP 200)',
  '3. Cùng AD: metric nhỏ hơn thắng',
  '',
  '## Định tuyến bất đối xứng (asymmetric)',
  'Đi đường này, về đường khác. Mạng thuần L3 thì vẫn chạy, nhưng qua FIREWALL là ĐỨT:',
  'firewall thấy gói về mà không có session tương ứng → drop. Đây là nguyên nhân kinh điển của',
  '"ping được nhưng TCP không lên" hoặc "chỉ hỏng khi đi qua firewall".',
  '',
  '## Kiểm tra',
  'Cisco    : show ip route <ip> · show ip cef <ip> · traceroute',
  'FortiGate: get router info routing-table all · get router info kernel · diagnose ip route list',
  'Linux    : ip r get <ip> (cho biết chính xác cửa ra và gateway)',
].join('\n');

KB['firewall-policy'] = [
  '# FIREWALL POLICY & NAT (FortiGate)',
  '',
  '## Trình tự khớp policy',
  'Duyệt từ TRÊN XUỐNG, khớp cái ĐẦU TIÊN rồi dừng. Policy đúng nhưng nằm dưới một policy rộng hơn',
  '= không bao giờ được dùng tới. Kiểm bằng cột hit count.',
  '',
  '## Session table — chìa khoá của mọi chẩn đoán',
  'Firewall làm việc theo SESSION, không theo từng gói. Hệ quả:',
  '  • Đổi policy KHÔNG tác động tới session đang chạy (phải clear hoặc chờ hết hạn)',
  '  • "diagnose sys session filter" + "diagnose sys session list" cho biết session có tồn tại,',
  '    đi cửa nào, có được NPU offload không',
  '',
  '## Local-in vs traffic đi xuyên qua',
  'Policy thường chỉ áp cho traffic ĐI XUYÊN QUA firewall. Traffic ĐẾN CHÍNH firewall (SSH/HTTPS quản trị,',
  'ping tới interface) do local-in policy và trustedhost quyết định. Soi nhầm chỗ này rất mất thời gian.',
  '',
  '## UTM và hiệu năng',
  'Bật AV/IPS/SSL-inspection = traffic rời khỏi phần cứng tăng tốc, lên CPU xử lý.',
  'Với luồng lớn liên tục (video, sao lưu, camera) đây là nguyên nhân nghẽn phổ biến nhất.',
  'Luồng nội bộ tin cậy (camera → NVR trong cùng hệ thống) thường KHÔNG cần UTM.',
  '',
  '## Chẩn đoán "vì sao bị chặn" — dùng debug flow, đừng đoán',
  'diagnose debug reset · diagnose debug flow filter addr <ip> · diagnose debug flow show function-name enable',
  '· diagnose debug enable · diagnose debug flow trace start 20   → xong nhớ "diagnose debug disable".',
  'Output cho biết chính xác khớp policy số mấy hoặc drop vì lý do gì.',
].join('\n');

KB['video-camera'] = [
  '# LUỒNG VIDEO / CAMERA GIÁM SÁT',
  '',
  '## Tính băng thông trước khi đổ lỗi cho mạng',
  'Camera 2MP (1080p) H.264 ~4 Mbps · H.265 ~2 Mbps · 4MP H.265 ~4 Mbps · 8MP (4K) H.265 ~8 Mbps.',
  '30 camera 2MP H.265 ≈ 60 Mbps — chưa tới 10% của một đường 1Gbps.',
  '→ Camera giật mà băng thông mới dùng 10% thì nguyên nhân KHÔNG phải thiếu băng thông.',
  'Nhớ nhân đôi nếu vừa ghi vào NVR vừa xem trực tiếp qua đường khác.',
  '',
  '## Nguyên nhân camera giật, theo thứ tự hay gặp',
  '1. CPU/đĩa của NVR hoặc máy chủ ghi hình quá tải (không phải mạng)',
  '2. Firewall bật UTM cho luồng video → nghẽn CPU firewall',
  '3. Nguồn PoE yếu / cáp kém → cổng lên xuống, lỗi CRC → mất gói',
  '4. Mất gói trên đường: đọc bộ đếm input/output errors, drop ở cả hai đầu',
  '5. Wi-Fi: camera qua Wi-Fi thì nhiễu/kênh chồng lấn là nguyên nhân số một',
  '6. Multicast không có IGMP snooping → traffic phát tràn toàn VLAN (xem dưới)',
  '',
  '## Unicast vs Multicast',
  'RTSP/ONVIF thông thường là UNICAST: mỗi người xem thêm một luồng riêng. 5 người xem 1 camera = 5 luồng.',
  'Multicast chỉ dùng khi hệ thống được thiết kế cho nó. Nếu có multicast mà switch KHÔNG bật IGMP snooping',
  'thì switch phát tràn ra mọi cổng như broadcast → mạng ngộp dù băng thông danh nghĩa còn nhiều.',
  'Kiểm: "show ip igmp snooping" (Cisco). Có multicast thì phải có snooping + một querier trong VLAN.',
  '',
  '## VLAN riêng cho camera',
  'Nên tách VLAN camera. Lợi: gọn miền broadcast, dễ đặt QoS, chặn camera ra Internet (camera là thiết bị',
  'hay có lỗ hổng, không nên cho ra ngoài). Nhưng nhớ: tách VLAN thì luồng camera→NVR khác VLAN sẽ phải',
  'đi qua firewall — cân nhắc đặt NVR CÙNG VLAN với camera để traffic ở lại tầng 2, không gánh lên firewall.',
].join('\n');

KB['toc-do-duplex-mtu'] = [
  '# TỐC ĐỘ / DUPLEX / MTU — mấy lỗi vật lý hay bị bỏ sót',
  '',
  '## Duplex mismatch',
  'Một đầu full, một đầu half (thường do một bên đặt cứng, một bên auto).',
  'Triệu chứng rất đặc trưng: mạng CHẠY ĐƯỢC nhưng chậm kinh khủng, càng tải càng chậm.',
  'Bằng chứng: late collision ở đầu half, FCS/CRC error ở đầu full.',
  'Cách chuẩn: để AUTO cả hai đầu. Đặt cứng thì phải đặt cứng CẢ HAI.',
  '',
  '## Lỗi cáp / SFP',
  'CRC error tăng = tín hiệu hỏng: cáp kém, đầu bấm lỗi, quá 100m, nhiễu, SFP không tương thích.',
  'Đổi cáp/cổng là cách kiểm nhanh nhất, đừng ngồi soi cấu hình.',
  '',
  '## MTU / MSS',
  'MTU mặc định 1500. Qua PPPoE (-8), VPN IPsec (-~60), GRE, VXLAN đều giảm.',
  'Triệu chứng kinh điển: ping nhỏ được, SSH gõ được vài chữ rồi treo, web tải dở dang,',
  'file nhỏ qua được file lớn thì hỏng. Đó là MTU/PMTUD chứ không phải "mạng chập chờn".',
  'Kiểm: ping với cờ không phân mảnh, giảm dần kích thước tới khi qua được',
  '  Windows: ping -f -l 1472 <ip>   Linux: ping -M do -s 1472 <ip>',
  'Chữa: sửa MTU cho khớp, hoặc kẹp MSS trên thiết bị biên (FortiGate: set tcp-mss-sender/receiver).',
  'Trong một EtherChannel/LAG, MTU lệch giữa các thành viên sẽ khiến cổng không gộp được.',
].join('\n');

KB['chan-doan'] = [
  '# QUY TRÌNH CHẨN ĐOÁN THEO TRIỆU CHỨNG',
  '',
  '## Nguyên tắc chung',
  'Khoanh vùng bằng cách CHIA ĐÔI đường đi, đừng dò tuần tự từ đầu.',
  'Mỗi phép thử phải loại bỏ được một nửa khả năng, nếu không thì đó là phép thử vô ích.',
  'Hỏi trước: "chuyện này bắt đầu từ khi nào, có ai vừa đổi gì không" — 80% sự cố đến từ một thay đổi.',
  '',
  '## "Hai máy không thấy nhau"',
  '1. Cùng VLAN hay khác VLAN? (quyết định soi L2 hay L3)',
  '2. Cùng VLAN: cổng có up không → MAC có học được ở switch không → VLAN có xuyên suốt các trunk không',
  '3. Khác VLAN: có ARP tới gateway không → gateway có route không → firewall có policy không',
  '4. Ping được mà dịch vụ không lên → nhảy thẳng xuống L4: cổng dịch vụ, policy, session',
  '',
  '## "Mạng chậm"',
  '1. Chậm cho ai: một máy / một VLAN / tất cả? (khoanh vùng ngay từ câu này)',
  '2. Kiểm bộ đếm lỗi cổng ở hai đầu đường nghi ngờ (CRC, drop, late collision)',
  '3. Kiểm tải: CPU switch/firewall, băng thông cổng uplink so với dung lượng đường',
  '4. Duplex mismatch (chậm bất thường khi có tải)',
  '5. Nếu qua firewall: UTM có bật cho luồng đó không, CPU firewall bao nhiêu',
  '6. Đừng quên: chậm có thể do máy chủ đích (đĩa/CPU), không phải mạng',
  '',
  '## "Lúc được lúc không"',
  'Nghi trước: MTU (file lớn hỏng, file nhỏ được) · định tuyến bất đối xứng · STP đang hội tụ lại',
  '· cổng lên xuống (interface resets tăng) · IP trùng (hai máy cùng IP, ARP nhảy MAC).',
  '',
  '## "Sau khi thay đổi X thì hỏng"',
  'Ưu tiên tuyệt đối: quay lại trạng thái trước đó rồi mới phân tích. Đừng chồng thêm thay đổi mới lên.',
].join('\n');

KB['an-toan-thao-tac'] = [
  '# AN TOÀN KHI THAO TÁC TRÊN THIẾT BỊ ĐANG CHẠY',
  '',
  '## Lệnh có thể TỰ CẮT ĐƯỜNG SSH của chính mình',
  'Đổi IP/mask interface quản trị · sửa allowed VLAN của trunk đang ngồi · shutdown cổng uplink',
  '· sửa route mặc định · sửa policy firewall đang cho phép quản trị · sửa cấu hình LAG đang dùng.',
  '',
  '## Cách làm an toàn',
  'Cisco: "reload in 10" trước khi sửa → mất kết nối thì thiết bị tự khởi động lại về cấu hình cũ',
  '  (nhớ "reload cancel" sau khi xác nhận vẫn vào được). Đây là lưới an toàn tốt nhất cho việc sửa từ xa.',
  'Sửa trunk: dùng "allowed vlan add/remove" thay vì gõ lại cả danh sách — gõ lại là dễ sót nhất.',
  'Luôn LƯU CẤU HÌNH TRƯỚC khi sửa lớn (copy run start / execute backup config) để còn đường lui.',
  'Nhớ lưu SAU khi sửa xong và đã xác nhận chạy đúng (Cisco/Aruba: write memory. FortiGate tự lưu).',
  '',
  '## Thứ tự an toàn khi làm nhiều bước',
  'Đọc trạng thái hiện tại → ghi lại để so sánh → sửa MỘT thứ → đọc lại xác nhận → mới sang bước kế.',
  'Sửa nhiều thứ cùng lúc thì hỏng không biết do cái nào.',
].join('\n');

/* Mục lục ngắn để nhét vào lời nhắc — chỉ tên + một dòng mô tả, không phải nội dung. */
var INDEX = [
  ['mo-hinh-mang',      'phân tầng OSI, 3-tier/collapsed core/spine-leaf, ranh giới L2-L3, gateway nằm đâu'],
  ['bang-chung',        'quy tắc kết luận: lệnh nào chứng minh được gì, khi nào ĐƯỢC đề xuất sửa'],
  ['doc-output-cisco',  'đọc đúng output Cisco: trunk, etherchannel, interface, vlan, stp, route'],
  ['doc-output-fortigate', 'FortiOS: lệnh nào hiện gì, đường đi gói tin, debug flow, NPU offload'],
  ['doc-output-aruba',  'Aruba/HPE: khác biệt cú pháp, chữ "trunk" nghĩa khác Cisco'],
  ['doc-output-linux',  'Linux: ip/ss/tcpdump/ethtool và bẫy ICMP bị chặn'],
  ['gop-cong',          'LACP/PAgP/static, cặp cấu hình hợp lệ, cờ trạng thái, vì sao gộp không nhân đôi 1 luồng'],
  ['vlan-trunk',        'VLAN, 802.1Q, native VLAN, điều kiện thông L2 xuyên switch, pruning'],
  ['stp',               'spanning-tree, dấu hiệu loop, root bridge, portfast/bpduguard'],
  ['dinh-tuyen',        'route hai chiều, longest match, định tuyến bất đối xứng qua firewall'],
  ['firewall-policy',   'thứ tự policy, session table, local-in, UTM và hiệu năng, debug flow'],
  ['video-camera',      'tính băng thông camera, nguyên nhân giật, unicast/multicast, IGMP snooping'],
  ['toc-do-duplex-mtu', 'duplex mismatch, lỗi CRC/cáp, MTU/MSS và triệu chứng đặc trưng'],
  ['chan-doan',         'quy trình theo triệu chứng: không thấy nhau, mạng chậm, lúc được lúc không'],
  ['an-toan-thao-tac',  'lệnh tự cắt SSH, reload in, cách sửa trunk an toàn, lưu cấu hình'],
];

/* ══════════════════════════════════════════════════════════════════════════
   SỔ ĐĂNG KÝ — để sau này thêm lĩnh vực mới mà KHÔNG phải sửa file này
   ──────────────────────────────────────────────────────────────────────────
   Mỗi lĩnh vực là MỘT FILE riêng, tự gọi window.__KB_ADD để ghi danh:

       ssh-field-kb.js         → mạng (file này)
       ssh-field-kb-linux.js   → Linux / server
       ssh-field-kb-<x>.js     → thêm sau: ảo hoá, wifi, thoại, camera…

   Thêm lĩnh vực = thêm 1 file + 1 dòng <script> trong ssh-field.html. Không đụng
   gì tới lời nhắc hệ thống, không đụng file cũ → ít rủi ro làm hỏng thứ đang chạy.

   ⚠️ CHỈ ĐƯỢC CHỨA KIẾN THỨC CHUNG (giao thức, cách đọc output, quy trình chẩn
   đoán). TUYỆT ĐỐI KHÔNG chứa dữ liệu công ty: IP thật, mật khẩu, tên máy chủ,
   sơ đồ mạng thật, tên khách hàng. Lý do: file này là asset công khai của trang
   và được gửi lên LLM khi AI tra cứu.
   Có script kiểm tự động: node tools/kiem-kho-kien-thuc.mjs (chạy trước khi deploy). */
window.__KB_ADD = function (linhVuc, topics, index) {
  Object.keys(topics).forEach(function (k) {
    if (KB[k]) console.warn('[KB] trùng tên mục:', k, '(lĩnh vực ' + linhVuc + ')');
    KB[k] = topics[k];
  });
  INDEX.push.apply(INDEX, index || []);
};

/* ══════════════════════════════════════════════════════════════════════════
   NẠP THÊM KHO DO ANH THOẠI TỰ VIẾT trong Settings → AI → 🎓 Dạy AI
   ──────────────────────────────────────────────────────────────────────────
   Mọi file có đường dẫn bắt đầu bằng "network/" trong kho đó sẽ thành một mục
   tra cứu ở đây. Sửa trong giao diện, bấm Lưu, tải lại trang là AI dùng được —
   KHÔNG phải sửa file .js, không phải deploy.

   Mục do anh viết ĐÈ LÊN mục dựng sẵn nếu trùng tên: người dùng biết hệ thống
   của mình rõ hơn kiến thức đóng hộp, nên ý anh phải thắng.

   Hỏng mạng / chưa cấp quyền thì im lặng bỏ qua — kho dựng sẵn vẫn chạy, trợ lý
   không được phép chết chỉ vì thiếu phần mở rộng. */
function napKhoTuSettings() {
  try {
    fetch('/api/kb/network', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.muc || !d.muc.length) return;
        var them = {}, idx = [];
        d.muc.forEach(function (m) {
          them[m.id] = m.noi_dung;
          /* Không thêm vào mục lục nếu đã có tên đó — tránh mục lục hiện hai lần */
          if (!INDEX.some(function (i) { return i[0] === m.id; })) {
            idx.push([m.id, (m.mo_ta || '') + '  (tự viết)']);
          }
          if (m.canh_bao && m.canh_bao.length) {
            console.warn('[KB] "' + m.duong_dan + '" ' + m.canh_bao.join(', ')
              + ' — kho được gửi lên LLM, nên bỏ dữ liệu nhạy cảm ra.');
          }
        });
        Object.keys(them).forEach(function (k) { KB[k] = them[k]; });
        INDEX.push.apply(INDEX, idx);
        console.log('[KB] đã nạp thêm ' + d.muc.length + ' mục từ Settings → Dạy AI');
      })
      .catch(function () {});
  } catch (e) {}
}
napKhoTuSettings();

window.__NET_KB = {
  /* Trả nội dung một hoặc nhiều mục. Cho tra nhiều mục một lần để đỡ tốn vòng gọi model. */
  get: function (topics) {
    var list = Array.isArray(topics) ? topics : String(topics || '').split(/[,\s]+/);
    var out = [], thieu = [];
    list.filter(Boolean).forEach(function (t) {
      var k = String(t).trim().toLowerCase();
      if (KB[k]) out.push(KB[k]); else thieu.push(k);
    });
    return { noi_dung: out.join('\n\n───────────────\n\n'), khong_co: thieu };
  },
  index: INDEX,
  /* Mục lục dạng chữ để nhét vào lời nhắc hệ thống (ngắn, chỉ tên + mô tả 1 dòng) */
  indexText: function () {
    return INDEX.map(function (i) { return '  • ' + i[0] + ' — ' + i[1]; }).join('\n');
  },
  topics: function () { return INDEX.map(function (i) { return i[0]; }); },
};
})();
