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
- Thỉnh thoảng chạy `dns update` để cập nhật Mosdns-x và lego lên phiên bản mới nhất.
