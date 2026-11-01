# Mosdns-x Native

### Cài đặt

```
wget -qO /home/setup-mosdns-x-native.sh https://go.bibica.net/mosdns-x && sudo bash /home/setup-mosdns-x-native.sh
```

- Chọn `1. Fresh Install`, sau đó nhập domain và Cloudflare API Token (tạo Token theo mẫu **Edit Zone.DNS**).
- Sau khi cài đặt, script sẽ hiển thị IP của VPS. Tạo bản ghi DNS trỏ domain về IP này trên Cloudflare, lưu ý **không bật Cloudflare Proxy (đám mây màu cam)**.

### Tự động cập nhật

SSL, bộ lọc quảng cáo và các thành phần liên quan được tự động gia hạn/cập nhật mỗi ngày lúc **2:00 sáng**.

### Sao lưu và khôi phục

Khi chuyển sang VPS mới:

- Sao chép toàn bộ dữ liệu trong thư mục `/home` từ VPS cũ sang VPS mới.
- Chạy lại script cài đặt `sudo bash /home/setup-mosdns-x-native.sh`
- Chọn `2. Restore` để khôi phục cấu hình và dữ liệu.

### Quản lý dịch vụ

Mosdns-x Native cung cấp sẵn các lệnh quản lý. Chỉ cần nhớ lệnh `dns`:

| Lệnh          | Chức năng                       |
| ------------- | ------------------------------- |
| `dns start`   | Khởi động dịch vụ               |
| `dns stop`    | Dừng dịch vụ                    |
| `dns restart` | Khởi động lại dịch vụ           |
| `dns status`  | Kiểm tra trạng thái             |
| `dns log`     | Xem nhật ký                     |
| `dns update`  | Cập nhật lên phiên bản mới nhất |
| `dns -v`      | Kiểm tra phiên bản              |

- Sử dụng `dns restart` sau khi thay đổi cấu hình để áp dụng các thiết lập mới.
- Thỉnh thoảng chạy `dns update` để cập nhật Mosdns-x và lego lên bản mới nhất.

### Geo Firewall v3 – Cài đặt tường lửa

Với các dịch vụ DNS public, nên cài firewall để hạn chế các kết nối rác từ tool và bot khác.

Mở file cấu hình:

```
nano /home/setup-geo-firewall.sh
```

Mặc định, firewall cho phép IP thuộc Việt Nam, Singapore, Nhật Bản và Hong Kong truy cập VPS.

Các port được phép truy cập:

- **TCP:** 22, 2224, 53, 443, 853
- **UDP:** 53, 443, 853

Cấu hình mặc định:

```
# Allowed countries (ISO 3166-1 alpha-2 codes)
ALLOW_COUNTRIES=("VN" "SG" "JP" "HK")

# Services to be protected (ports open to allowed countries)
ALLOW_TCP_PORTS=("53" "443" "853")
ALLOW_UDP_PORTS=("53" "443" "853")

# GeoIP protected, but no rate-limit (e.g. SSH)
NO_RATELIMIT_TCP_PORTS=("22" "2224")

# Allow ICMP echo-request (ping) from allowed countries
ENABLE_PING=false

# RATE LIMIT (per IP, per port)
# If an IP sends more than RATE packets/sec (after BURST absorbed), it gets penalized.
# While penalized, only THROTTLE_RATE packets/sec are allowed for PENALTY_TIME seconds.
ENABLE_RATE_LIMIT=true

RATE_LIMIT_UDP=250          # Max packets/sec per IP (UDP)
RATE_LIMIT_TCP=500          # Max packets/sec per IP (TCP)

BURST_UDP=5000              # Allowed spike before rate-limit kicks in
BURST_TCP=5000              # Allowed spike before rate-limit kicks in

THROTTLE_RATE=5             # Packets/sec allowed while penalized
PENALTY_TIME=5              # Penalty duration (seconds, auto-refreshed if abuse continues)
```

Nếu cần mở thêm port, bổ sung vào danh sách tương ứng:

- `ALLOW_TCP_PORTS`: Port TCP có áp dụng Rate Limit.
- `ALLOW_UDP_PORTS`: Port UDP có áp dụng Rate Limit.
- `NO_RATELIMIT_TCP_PORTS`: Port TCP được bảo vệ bằng GeoIP nhưng không áp dụng Rate Limit.

Các cấu hình liên quan đến `RATE LIMIT` nên giữ nguyên mặc định. Giới hạn này đủ lớn, người dùng thông thường sẽ không bao giờ sử dụng hết.

Sau khi điều chỉnh, chạy script cài đặt firewall:

```
/home/setup-geo-firewall.sh
```

DoH, DoT, DoQ và DoH3 đã được cấu hình mở port sẵn. Nếu VPS chạy trên các dịch vụ cloud như Amazon, Google, Oracle, Tencent..., cần vào trang quản trị nhà cung cấp để mở thêm các port:

- **TCP:** 53, 443, 853
- **UDP:** 53, 443, 853
