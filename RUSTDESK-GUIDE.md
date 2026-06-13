# Hướng dẫn sử dụng RustDesk Self-Hosted
> Server: `192.168.110.21` · Admin panel: `http://192.168.110.21:21114/_admin/`  
> Key hiện tại: `YOURKEY`

---

## Mục lục
1. [Tổng quan hệ thống](#1-tổng-quan)
2. [Quản lý Users](#2-quản-lý-users)
3. [Quản lý Groups](#3-quản-lý-groups)
4. [Peers — Danh sách thiết bị](#4-peers)
5. [Device Group Manage](#5-device-group-manage)
6. [Address Books](#6-address-books)
7. [Tags](#7-tags)
8. [Logs — Xem lịch sử](#8-logs)
9. [Deploy hàng loạt lên máy nhân viên](#9-deploy-hàng-loạt)
10. [Kết nối từ xa](#10-kết-nối-từ-xa)

---

## 1. Tổng quan

```
Máy nhân viên / học sinh
     │  (cài RustDesk agent)
     ▼
RustDesk Server (CasaOS 192.168.110.21)
  ├── hbbs  :21116  ← đăng ký ID, kết nối
  ├── hbbr  :21117  ← relay khi không P2P được
  └── API   :21114  ← web admin, quản lý user/device
     │
     ▼
Máy anh (cài RustDesk client → remote vào máy khác)
```

**Luồng kết nối:**
1. Máy nhân viên cài agent → tự đăng ký lên server → có ID số
2. Anh mở RustDesk → nhập ID máy nhân viên → bấm Connect
3. Nhân viên thấy popup → Accept → anh vào được máy

---

## 2. Quản lý Users

### Tạo tài khoản cho nhân viên
`Admin panel → Users → Add`

| Trường | Điền gì |
|--------|---------|
| Username | tên đăng nhập (vd: `nguyen.van.a`) |
| Password | mật khẩu |
| Group | chọn nhóm phòng ban |
| Role | `User` (nhân viên thường) hoặc `Admin` |

**Tại sao cần tạo user?**
- Nhân viên đăng nhập vào RustDesk bằng account này
- Máy họ tự động gắn vào đúng nhóm
- Anh thấy tên người dùng thay vì chỉ thấy ID số

### Phân quyền
- **Admin**: xem tất cả máy, remote bất kỳ máy nào
- **User**: chỉ thấy máy trong nhóm của mình

---

## 3. Quản lý Groups

`Admin panel → Groups`

Mặc định có 2 nhóm:
- **默认组** (Default Group): nhóm chung
- **共享组** (Shared Group): nhóm chia sẻ

### Nên tạo nhóm theo phòng ban
`Add → đặt tên tiếng Việt`

Ví dụ:
```
Nhân viên Kế toán
Nhân viên IT
Phòng học A
Phòng học B
```

**Lợi ích**: Khi anh remote, dễ tìm máy theo phòng. Nhân viên chỉ thấy máy cùng nhóm.

---

## 4. Peers

`Admin panel → Peers`

Danh sách **tất cả thiết bị** đã kết nối vào server.

| Cột | Ý nghĩa |
|-----|---------|
| ID | Số ID của máy (dùng để kết nối) |
| Hostname | Tên máy tính |
| Username | Tên Windows user đang đăng nhập |
| OS | Windows/Linux/Mac |
| Last Online | Lần cuối online |
| Group | Thuộc nhóm nào |

**Tip**: Click vào máy → thấy thông tin chi tiết + lịch sử kết nối của máy đó.

---

## 5. Device Group Manage

`Admin panel → Device Group Manage`

Gán máy vào nhóm **thủ công** (khi máy chưa tự vào đúng nhóm).

**Cách dùng:**
1. Vào Device Group Manage
2. Tìm máy theo ID hoặc hostname
3. Chọn nhóm → Save

---

## 6. Address Books

`Admin panel → Address Books`

Giống **danh bạ** — lưu danh sách máy hay dùng để remote nhanh.

### Tạo Address Book
1. `Address Book Names → Add` → đặt tên (vd: "Máy IT", "Phòng học A")
2. `Address Books → Add` → chọn address book → thêm máy vào

**Lợi ích**: Mở RustDesk client → tab Address Book → thấy ngay danh sách máy hay dùng, không cần nhớ ID số.

---

## 7. Tags

`Admin panel → Tags`

Gắn nhãn màu cho thiết bị để phân loại nhanh.

Ví dụ:
- 🔴 `Cần hỗ trợ`
- 🟡 `Đang bảo trì`  
- 🟢 `Bình thường`

---

## 8. Logs

### Connection Log
`Admin panel → Connection Log`

Xem **ai remote vào máy nào**, lúc mấy giờ, bao lâu.

| Cột | Ý nghĩa |
|-----|---------|
| From | Máy thực hiện kết nối |
| To | Máy được remote vào |
| Time | Thời điểm kết nối |
| Duration | Thời gian phiên |
| Type | Remote / File transfer |

### Login Log
Xem ai đăng nhập vào admin panel, từ IP nào.

### File Log
Xem lịch sử **transfer file** qua RustDesk (ai gửi file cho ai).

---

## 9. Deploy hàng loạt lên máy nhân viên

### Tạo file script `install-rustdesk.bat`

```bat
@echo off
echo Dang cai RustDesk...

REM Cai silent
msiexec /i "%~dp0RustDesk.msi" /quiet /qn

timeout /t 8 /nobreak >nul

REM Ghi config server tu dong
set CFG=C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config
mkdir "%CFG%" 2>nul

(
echo rendezvous_server = '192.168.110.21'
echo nat_type = 1
echo serial = 0
echo.
echo [options]
echo custom-rendezvous-server = '192.168.110.21'
echo key = 'YOURKEY'
echo relay-server = '192.168.110.21'
echo api-server = 'http://192.168.110.21:21114'
) > "%CFG%\RustDesk2.toml"

net stop rustdesk >nul 2>&1
net start rustdesk >nul 2>&1

echo Hoan tat! May nay da san sang ket noi.
pause
```

### Chuẩn bị USB/folder deploy
```
📁 deploy-rustdesk/
  ├── RustDesk.msi          ← tải tại rustdesk.com
  └── install-rustdesk.bat
```

### Chạy trên máy nhân viên
1. Copy folder vào máy
2. Chuột phải `install-rustdesk.bat` → **Run as Administrator**
3. Chờ ~15 giây → xong

Máy tự động xuất hiện trong **Peers** trên admin panel.

---

## 10. Kết nối từ xa

### Cách 1 — Nhập ID trực tiếp
1. Mở RustDesk trên máy anh
2. Nhập ID của máy cần remote (lấy từ Peers)
3. Bấm **Connect**
4. Nhập password hiển thị trên máy nhân viên (hoặc dùng permanent password)

### Cách 2 — Qua Address Book (nhanh hơn)
1. Mở RustDesk → tab **Address Book**
2. Click vào tên máy → **Connect**

### Thiết lập Permanent Password (không cần hỏi mỗi lần)
Trên máy nhân viên: RustDesk → **⋮** (ba chấm cạnh password) → **Set permanent password**  
Anh lưu password đó lại → lần sau kết nối không cần hỏi nhân viên.

### Chế độ kết nối
| Chế độ | Nhân viên thấy gì |
|--------|-------------------|
| **Request** (mặc định) | Popup xin phép → phải Accept |
| **View only** | Chỉ xem, không điều khiển |
| **File transfer** | Chỉ chuyển file, không thấy màn hình |

---

## Lưu ý quan trọng

> ⚠️ **Đổi key sau khi ổn định**  
> Key hiện tại `YOURKEY` là mặc định không an toàn.  
> Sau khi deploy xong tất cả máy, đổi key trong docker-compose của hbbs và cập nhật lại config trên tất cả máy client.

> 💡 **Máy cần online**  
> Máy nhân viên phải đang bật và có mạng thì mới remote được.  
> Nếu máy tắt → không kết nối được (khác camera).

> 🔒 **Bảo mật**  
> Không expose port 21116/21117 ra internet nếu không cần thiết.  
> Chỉ expose qua CF Tunnel khi cần remote từ ngoài công ty.
