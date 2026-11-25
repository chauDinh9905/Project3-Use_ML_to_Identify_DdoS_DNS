# Ghi chú Bước 3 - Tiền xử lý và chọn đặc trưng

Nguồn: `reports/buoc3_tien_xu_ly.txt`.

## Số dòng qua từng bước xử lý

| Bước | Số dòng | Ghi chú |
|---|---|---|
| Dữ liệu gốc (8 file DrDoS_* ngày 01-12) | 28.001.999 | |
| Sau khử trùng trong từng file | 2.641.358 | Giữ 9,4% |
| Sau khử trùng BENIGN giữa các file | 2.640.662 | −696 |
| Sau loại vector mang cả BENIGN lẫn tấn công | 2.640.573 | −89 dòng (30 vector) |
| **Tập DNS + BENIGN** (`dns_binary.parquet`) | **60.222** | 35.485 DrDoS_DNS + 24.737 BENIGN |

**Tỉ lệ giữ lại theo file**

| File | Gốc | Sau khử trùng | Giữ |
|---|---|---|---|
| DrDoS_DNS | 5.074.413 | 38.577 | 0,76% |
| DrDoS_LDAP | 2.181.542 | 6.426 | 0,29% |
| DrDoS_MSSQL | 4.524.498 | 18.255 | 0,40% |
| DrDoS_NetBIOS | 4.094.986 | 10.809 | 0,26% |
| DrDoS_NTP | 1.217.007 | 1.111.079 | 91,30% |
| DrDoS_SNMP | 5.161.377 | 15.909 | 0,31% |
| DrDoS_SSDP | 2.611.374 | 658.530 | 25,22% |
| DrDoS_UDP | 3.136.802 | 781.773 | 24,92% |

## Nhận xét

### 1. Khử trùng thay đổi hoàn toàn bản chất bài toán

- **DNS chỉ còn 35.485 vector khác nhau** trên 5.071.011 flow, tức trung bình mỗi vector lặp lại khoảng 143 lần. Con số này còn thấp hơn mức 116.331 ở EDA, vì Bước 3 đã bỏ 4 cột lỗi tràn số (Fwd Header Length...). Các cột lỗi đó tạo ra khác biệt giả giữa những flow vốn giống hệt nhau.
- **Mất cân bằng gần như biến mất:** trước khử trùng, tỉ lệ BENIGN : DNS là khoảng 1 : 1.490; sau khử trùng là 24.737 : 35.485, tức khoảng 1 : 1,4. Bước 4 không cần lấy mẫu bớt lớp tấn công; dùng trọng số lớp là đủ.
- **Bài toán khó hơn EDA gợi ý.** EDA bị chi phối bởi hàng triệu bản sao của vài vector phổ biến (2 gói × 1.472 byte). Sau khử trùng, mỗi kiểu flow chỉ được đếm một lần, nên các flow tấn công "khác thường" chiếm tỉ trọng lớn hơn nhiều. Bằng chứng: mutual information cao nhất chỉ đạt 0,553, khoảng 82% mức tối đa (xem mục 4). Tức là không đặc trưng nào một mình tách được hoàn toàn hai lớp.
- NTP, SSDP và UDP giữ lại nhiều hơn hẳn (25–91%), nghĩa là lưu lượng tấn công của các file này đa dạng hơn nhiều so với DNS.

### 2. Xung đột nhãn

- **BENIGN lẫn tấn công:** chỉ 30 vector (89 dòng), đã loại. Nhiễu nhãn kiểu này không đáng kể.
- **Giữa các kiểu tấn công:** 102.210 vector, được giữ và gắn cờ `xung_dot_tan_cong`.
  - **DrDoS_SSDP và DrDoS_UDP trùng 91.556 vector,** chiếm khoảng 14% số dòng của mỗi file sau khử trùng. Ở mức flow, UDP flood và SSDP reflection trong dữ liệu này rất khó phân biệt.
  - **8.193 dòng DNS (23% của 35.485) có vector trùng với kiểu tấn công khác,** chủ yếu MSSQL, SNMP và LDAP. Đây là số liệu trực tiếp cho câu hỏi nghiên cứu RQ3 ("DNS dễ bị nhầm với giao thức nào"). Nó cũng khớp với điều đã thấy trong bản Kaggle ở đầu dự án.

### 3. Nhãn đáng nghi

- 1.472 dòng DrDoS_DNS (4,1%) có `nghi_sai_nhan = true` (không đi từ 172.16.0.5 hoặc không phải UDP). Bước 4 so sánh mô hình có và không có các dòng này.

### 4. Chia tập

- Mỗi tập giữ tỉ lệ BENIGN : DNS như nhau (khoảng 41% : 59%): train 36.133, val 12.044, test 12.045.
- Mức tối đa của mutual information trên tập train là entropy của nhãn, khoảng 0,68 nat.
- Với `split_thoi_gian`, phiên bản đầu của script lấy Timestamp của một bản trùng bất kỳ, nên khung thời gian của ba tập không đáng tin. **Đã sửa** để lấy thời điểm xuất hiện đầu tiên của mỗi vector. Sau khi chạy lại, tập test chứa những kiểu flow *lần đầu xuất hiện* ở cuối đợt tấn công: đây là định nghĩa "chưa từng thấy" đúng nghĩa.

### 5. Chọn đặc trưng

- Loại 12 cột hằng số (giống hệt danh sách ở EDA) và 16 cột tương quan |r| > 0,98, còn **48 đặc trưng**.
- Các cặp tương quan đáng chú ý:
  - `RST Flag Count` trùng hoàn toàn với `Fwd PSH Flags` (r = 1,0), lỗi đã biết của CICFlowMeter, cũng đã thấy trong bản Kaggle.
  - 4 cột Subflow trùng hoàn toàn với 4 cột Total tương ứng.
  - `Average Packet Size` gần trùng với `Packet Length Mean` (r = 0,98) dù có lỗi công thức thấy ở EDA.
- **Top mutual information:** đứng đầu là nhóm kích thước gói (Fwd Packet Length Min, Packet Length Mean, Max Packet Length...) và nhóm tốc độ (Flow Bytes/s, Flow Packets/s), khớp với nhận xét từ hình phân phối ở Bước 2.
- **Cần lưu ý:**
  - `Inbound` đứng thứ 10 (0,426). Cột này đánh dấu chiều của flow so với mạng nội bộ, nên có thể đóng vai trò gần giống cột định danh. Nên thử bỏ nó trong thí nghiệm ablation ở Bước 4.
  - Nhiều cột Bwd (Bwd Packets/s, Bwd IAT...) điểm cao chỉ vì tấn công không có chiều ngược nên các cột này luôn bằng 0. Chúng mang chung một thông tin: "có phản hồi hay không".