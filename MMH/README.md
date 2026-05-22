# Mô Phỏng Tấn Công Håstad's Broadcast (RSA Low Exponent Attack)

Ứng dụng giao diện (GUI) minh họa và phân tích lỗ hổng bảo mật của mã hóa RSA khi sử dụng số mũ công khai nhỏ trong kịch bản gửi trùng một thông điệp cho nhiều người nhận.

## Tính năng chính: Ứng dụng gồm 3 tính năng

* **Sinh Khóa / Mã Hóa:**
    * Đầu vào: Nhập vào số mũ công khai e và chuỗi plaintext.
    * Chức năng: Khởi tạo cặp khóa RSA tiêu chuẩn (Khóa công khai và Khóa bí mật) với kích thước tùy chỉnh.
    * Thực hiện mã hóa thông điệp và kiểm thử tính đúng đắn bằng phép giải mã hoặc khai căn trực tiếp.

* **Tấn công Håstad:**
    * Mô phỏng toàn bộ kịch bản thực tế khi một thông điệp được mã hóa và gửi tới e người nhận khác nhau.
    * Hệ thống tự động thu thập các cặp bản mã C_i và Modulus N_i.
    * Sau đó áp dụng Định lý số dư Trung Hoa (CRT) và phép khai căn bậc e để khôi phục lại bản rõ ban đầu mà không cần đến khóa bí mật d.

* **Trực quan hóa điều kiện:**
    * Tiến hành so sánh điều kiện khi m nhỏ và m lớn, e nhỏ và e lớn.

---

## Cách thực thi tệp

### Cài đặt thư viện đầu vào:
```bash
pip install gmpy2 sympy pytest
```

### Chạy tệp gui_app.py:
```bash
python gui_app.py
```



