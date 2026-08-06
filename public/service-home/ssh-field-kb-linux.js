/* ═══════════════════════════════════════════════════════════════════════════
   ssh-field-kb-linux.js — kiến thức LINUX / SERVER cho trợ lý SSH Hiện trường
   ───────────────────────────────────────────────────────────────────────────
   File này CHỈ ghi danh thêm mục vào kho, không sửa gì của phần mạng.
   Xem cách mở rộng ở cuối ssh-field-kb.js.

   ⚠️ CHỈ KIẾN THỨC CHUNG. Không IP thật, không mật khẩu, không tên máy chủ của
   công ty, không sơ đồ hệ thống thật.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
'use strict';
if (!window.__KB_ADD) { console.warn('[KB] chưa nạp ssh-field-kb.js trước'); return; }

var T = {};

T['linux-chan-doan'] = [
  '# CHẨN ĐOÁN LINUX — thứ tự soi khi "server có vấn đề"',
  '',
  '## Bốn câu hỏi đầu tiên, theo đúng thứ tự này',
  '1. Máy còn sống và tải thế nào?  uptime · top -bn1 | head -15',
  '   Load average so với số nhân (nproc). Load 8 trên máy 8 nhân = đầy nhưng chưa quá tải.',
  '   Load cao mà CPU rảnh → gần như chắc chắn là chờ I/O (đĩa hoặc mạng), xem cột "wa" trong top.',
  '2. Đĩa còn chỗ không?  df -h · df -i',
  '   ⚠️ df -i (inode) hay bị quên: còn dung lượng nhưng HẾT INODE thì vẫn không ghi được file mới.',
  '   Triệu chứng giống hệt hết đĩa nhưng df -h vẫn thấy trống.',
  '3. RAM và swap:  free -m',
  '   Linux dùng RAM làm cache là BÌNH THƯỜNG — nhìn cột "available", đừng nhìn "free".',
  '   Swap đang bị dùng nhiều + si/so trong vmstat khác 0 = đang thiếu RAM thật.',
  '4. Dịch vụ có chạy không:  systemctl status <tên> · systemctl --failed',
  '',
  '## Nhật ký — nơi có câu trả lời thật',
  'journalctl -u <dịch vụ> -n 100 --no-pager     : log của một dịch vụ',
  'journalctl -p err -b --no-pager               : mọi lỗi từ lần khởi động này',
  'journalctl --since "10 min ago" --no-pager    : chuyện vừa xảy ra',
  'dmesg -T | tail -50                           : lỗi phần cứng, OOM killer, lỗi đĩa',
  '⚠️ Tìm "Out of memory: Killed process" trong dmesg — OOM killer giết tiến trình là nguyên nhân',
  'kinh điển của "tự nhiên dịch vụ chết mà log dịch vụ không ghi gì".',
  '',
  '## Tiến trình nào ăn tài nguyên',
  'top -bn1 -o %CPU | head -20 · top -bn1 -o %MEM | head -20',
  'ps aux --sort=-%mem | head · pidstat 1 5 (nếu có sysstat)',
  'iotop -bn2 (đĩa) · nếu không có: cat /proc/<pid>/io',
].join('\n');

T['linux-mang'] = [
  '# LINUX — PHẦN MẠNG',
  '',
  '## Bộ lệnh hiện đại (ip) thay cho bộ cũ (ifconfig/netstat/route)',
  'ip a                : địa chỉ, trạng thái UP/DOWN của interface',
  'ip -s link          : bộ đếm gói và LỖI/DROP theo interface — bằng chứng mất gói tại máy',
  'ip r                : bảng định tuyến',
  'ip r get <ip>       : ⭐ cho biết CHÍNH XÁC gói tới <ip> sẽ đi cửa nào, gateway nào, nguồn IP nào',
  'ip neigh            : bảng ARP (tương đương arp -a)',
  'ss -tlnp            : cổng TCP đang NGHE + tiến trình nào giữ',
  'ss -tnp state established : kết nối đang mở',
  'ethtool <if>        : tốc độ/duplex thật của card · ethtool -S <if> : bộ đếm chi tiết của driver',
  '',
  '## Kiểm thông tới đâu — chọn đúng công cụ',
  'ping     : chỉ chứng minh ICMP thông. ICMP bị chặn KHÔNG có nghĩa dịch vụ hỏng.',
  'nc -vz <ip> <port> : kiểm đúng cổng TCP — sát với thực tế dịch vụ hơn ping nhiều.',
  'curl -v --max-time 5 <url> : kiểm cả tầng ứng dụng, thấy được lỗi TLS/HTTP.',
  'traceroute -n / mtr -n : đường đi và chỗ mất gói (mtr chạy liên tục, thấy tỉ lệ mất gói theo chặng).',
  'dig <tên> @<dns>  : phân giải tên. Rất nhiều "lỗi mạng" thật ra là lỗi DNS.',
  'tcpdump -ni <if> host <ip> and port <p> -c 50 : bằng chứng mạnh nhất — gói CÓ tới máy này không.',
  '  → Gói tới mà dịch vụ không trả lời = lỗi ở máy. Gói không tới = lỗi ở đường/firewall.',
  '',
  '## Tường lửa trên chính máy Linux (hay bị bỏ sót)',
  'iptables -L -n -v --line-numbers · nft list ruleset · firewall-cmd --list-all · ufw status verbose',
  'Cột pkts/bytes trong iptables -v cho biết luật nào ĐANG thật sự chặn gói.',
  'SELinux cũng chặn được kết nối mà không ghi vào log dịch vụ: getenforce · ausearch -m avc -ts recent',
].join('\n');

T['linux-dich-vu'] = [
  '# LINUX — DỊCH VỤ, CONTAINER, LƯU TRỮ',
  '',
  '## systemd',
  'systemctl status <svc>      : đang chạy? khởi động lần cuối lúc nào? lỗi gì?',
  'systemctl is-enabled <svc>  : có tự chạy khi khởi động máy không (khác với "đang chạy")',
  'systemctl daemon-reload     : bắt buộc sau khi sửa file .service, quên là sửa xong không ăn',
  'systemctl list-units --failed : mọi thứ đang hỏng, xem một lượt',
  '',
  '## Docker / container',
  'docker ps -a              : container nào chạy/chết, cột STATUS cho biết restart liên tục không',
  'docker logs --tail 100 <tên>  : log ứng dụng bên trong',
  'docker stats --no-stream  : CPU/RAM từng container',
  'docker inspect <tên> | grep -i -A5 restart : chính sách khởi động lại',
  '⚠️ Container "Restarting (1) 5 seconds ago" = đang chết đi sống lại liên tục, đọc logs là ra lý do.',
  '⚠️ Mạng container: cổng phải được publish (-p) mới ra ngoài được; container cùng network mới gọi',
  '   nhau bằng tên. "docker network inspect <net>" để xem ai cùng mạng với ai.',
  '',
  '## Lưu trữ',
  'df -h · df -i · du -sh /* 2>/dev/null | sort -h : tìm thư mục ngốn chỗ',
  'lsblk · blkid · mount | column -t : phân vùng và điểm gắn',
  'smartctl -H /dev/sdX : sức khoẻ đĩa (nếu có smartmontools)',
  '⚠️ File đã xoá mà tiến trình còn giữ thì dung lượng KHÔNG được trả lại: lsof +L1',
  '   Đây là lý do "xoá log rồi mà df vẫn đầy" — phải khởi động lại tiến trình đang giữ file.',
].join('\n');

T['linux-phoi-hop-mang'] = [
  '# PHỐI HỢP SERVER LINUX VỚI THIẾT BỊ MẠNG',
  '',
  '## Nguyên tắc: soi TỪ HAI PHÍA của cùng một đường',
  'Một sự cố "server không truy cập được" luôn có 3 khả năng, phải tách bạch:',
  '  A. Gói không rời khỏi máy nguồn        → kiểm tại nguồn: ip r get, tcpdump ở interface ra',
  '  B. Gói bị chặn/lạc trên đường          → kiểm switch/firewall giữa đường',
  '  C. Gói tới đích nhưng đích không trả lời → tcpdump tại đích, ss xem cổng có nghe không',
  'Chạy tcpdump ĐỒNG THỜI ở hai đầu là cách nhanh nhất để biết đứt ở khúc nào.',
  '',
  '## Đối chiếu giữa Linux và thiết bị mạng',
  'MAC của server (ip a) ⇄ MAC học được trên switch (show mac address-table) → chứng minh L2 thông tới cổng nào',
  'IP/mask của server (ip a) ⇄ VLAN + SVI/gateway trên switch/firewall → cùng subnet chưa, gateway đúng chưa',
  'MTU của server (ip a) ⇄ MTU của interface mạng → lệch là lỗi kiểu "file lớn thì hỏng"',
  'Tốc độ/duplex (ethtool) ⇄ show interfaces trên switch → hai đầu phải khớp',
  'Bonding của Linux (cat /proc/net/bonding/bond0) ⇄ LACP/EtherChannel phía switch',
  '  → mode 802.3ad ở Linux phải gặp LACP ở switch. mode balance-rr gặp LACP là KHÔNG lên.',
  '',
  '## Thứ tự soi khi "server không ra được Internet"',
  '1. ip a       — có IP đúng dải chưa (169.254.x.x = DHCP hỏng)',
  '2. ip r       — có default route chưa',
  '3. ping gateway — L2/L3 tới gateway có thông không',
  '4. ping 1.1.1.1 — ra ngoài được không (loại trừ DNS)',
  '5. dig @1.1.1.1 example.com — DNS có phân giải được không',
  '6. Ra được IP mà không ra được tên = lỗi DNS, KHÔNG phải lỗi mạng.',
  '',
  '## Múi giờ / đồng hồ',
  'timedatectl · chronyc sources · ntpq -p',
  'Đồng hồ lệch giữa server và thiết bị mạng làm log không đối chiếu được theo mốc thời gian,',
  'và làm hỏng xác thực (Kerberos, chứng chỉ TLS, TOTP). Kiểm sớm khi soi sự cố xác thực.',
].join('\n');

window.__KB_ADD('linux', T, [
  ['linux-chan-doan',     'Linux: thứ tự soi tải/đĩa/RAM/dịch vụ, đọc log, OOM killer, hết inode'],
  ['linux-mang',          'Linux: ip/ss/tcpdump/ethtool, kiểm cổng đúng cách, tường lửa tại máy, SELinux'],
  ['linux-dich-vu',       'Linux: systemd, docker/container, lưu trữ, file đã xoá còn giữ chỗ'],
  ['linux-phoi-hop-mang', 'ghép server Linux với switch/firewall: soi hai phía, đối chiếu MAC/MTU/bonding'],
]);
})();
