# Ghi chú EDA - DrDoS_DNS (01/12/2018)

Nguồn: `reports/buoc2_eda.txt`, chạy `src/eda_dns.py` trên `data/parquet/DrDoS_DNS.parquet`.

## Quy mô

- Số dòng: 5.074.413 | BENIGN: 3.402 (0,067%) | DrDoS_DNS: 5.071.011 (99,933%)
- Tỉ lệ BENIGN : tấn công ≈ 1 : 1.490
- 87 cột, trong đó 79 cột đặc trưng số

## Chất lượng dữ liệu

**Giá trị vô cực và thiếu**

| Cột | null | inf |
|---|---|---|
| Flow Bytes/s | 31 | 162.363 |
| Flow Packets/s | 0 | 162.394 |

Vô cực xuất hiện khi Flow Duration = 0 (chia cho 0). Chỉ 2 cột này bị ảnh hưởng, khoảng 3,2% số dòng.

**Giá trị âm**

| Cột | Số dòng âm | Nguyên nhân |
|---|---|---|
| Init_Win_bytes_forward | 5.071.044 | Giá trị −1 = "không áp dụng" (UDP không có cửa sổ TCP) |
| Init_Win_bytes_backward | 5.071.951 | Như trên |
| Fwd Header Length | 1.852.956 (36,5%) | Lỗi tràn số của CICFlowMeter |
| Fwd Header Length.1 | 1.852.956 | Như trên |
| min_seg_size_forward | 1.853.001 | Lỗi tràn số của CICFlowMeter |
| Bwd Header Length | 12 | Lỗi tràn số của CICFlowMeter |

**Cột thừa**

- 12 cột hằng số, trùng khớp với 12 cột đã thấy trong bản Kaggle: Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, FIN Flag Count, PSH Flag Count, ECE Flag Count và 6 cột *Bulk*.
- `Fwd Header Length.1` là bản sao của `Fwd Header Length` (cùng số dòng âm), do CICFlowMeter xuất trùng cột.

**Trùng lặp: rất nghiêm trọng**

- Chỉ có **116.331 vector đặc trưng khác nhau** trên 5.074.413 dòng.
- **4.958.082 dòng trùng (97,7%)**. Trong lớp tấn công, 4.997.374 dòng thuộc các nhóm trùng; trong BENIGN, 425 dòng.
- 4 vector đặc trưng mang cả nhãn BENIGN lẫn DrDoS_DNS.
- Hệ quả: nếu chia train/test ngẫu nhiên mà chưa khử trùng, các dòng giống hệt nhau sẽ nằm ở cả hai tập và điểm số bị thổi phồng.

## Cổng, IP, giao thức

**Giao thức**

| Nhãn | TCP (6) | UDP (17) | Khác (0) |
|---|---|---|---|
| BENIGN | 2.068 (60,8%) | 1.147 (33,7%) | 187 (5,5%) |
| DrDoS_DNS | 1.301 | 5.069.515 (99,97%) | 195 |

BENIGN có một phần ba là UDP, nên mô hình không thể chỉ dựa vào giao thức. Tuy vậy, có 1.496 dòng mang nhãn DrDoS_DNS nhưng không phải UDP, đáng nghi là gán nhãn sai.

**IP**

- Tấn công: **chỉ 2 IP**. 5.069.061 flow đi từ `172.16.0.5` đến `192.168.50.1` (web server nạn nhân); 1.950 flow theo chiều ngược lại.
- BENIGN: 137 IP nguồn, 149 IP đích. Gồm các máy nội bộ `192.168.50.6/7/8`, máy chủ DNS công cộng `4.2.2.4` và `8.8.8.8`, và các dịch vụ web bên ngoài.
- Một cột IP đã đủ phân biệt gần như hoàn hảo hai lớp, nên **phải bỏ khi huấn luyện** để tránh rò rỉ.

**Cổng**

- Cổng nguồn của tấn công: 2.652 giá trị khác nhau, tập trung ở dải 500–900. Phổ biến nhất là 564 (674.781 flow, 13,3%), sau đó 634, 900, 530, 512...
- Cổng đích của tấn công: 65.533 giá trị khác nhau, gần như ngẫu nhiên trên toàn dải.
- Cổng 53 gần như không xuất hiện trong lưu lượng tấn công. Trong BENIGN, 1.125 flow (33,1%) có cổng đích 53, chủ yếu là truy vấn tới `4.2.2.4` và `8.8.8.8`.
- **Giả thuyết phân mảnh: không được ủng hộ.** Cổng 0 chỉ có 195 dòng tấn công, quá ít để giải thích việc thiếu cổng 53.

**Diễn giải.** Lưu lượng tấn công đến từ **một IP duy nhất**, với cổng nguồn không phải 53 và cổng đích ngẫu nhiên. Tấn công DNS reflection thật sẽ đến từ hàng nghìn resolver khác nhau, đều từ cổng nguồn 53. Như vậy trong testbed, lưu lượng "DNS reflection" nhiều khả năng được **mô phỏng** (hoặc đi qua NAT/firewall làm thay đổi IP và cổng), và không mang các dấu hiệu đặc trưng của phản hồi DNS thật. Đây là một **hạn chế quan trọng của dữ liệu**, cần đưa vào báo cáo.

## Thời gian và nhãn

- Dữ liệu kéo dài từ 10:51:39 đến 11:22:40 ngày 01/12/2018.
- **Khung giờ UNB công bố (10:52–11:05) không khớp với dữ liệu.** Chỉ 15.317 dòng DrDoS_DNS (0,3%) nằm trong khung này. Đợt tấn công thực sự diễn ra **từ 11:06 đến 11:16**, khoảng 460.000–520.000 flow mỗi phút, chiếm khoảng 99,7% số dòng tấn công.
- Trong khung 10:51–11:05 chỉ có vài trăm đến khoảng 2.400 flow tấn công mỗi phút. Sau 11:17, con số giảm xuống vài chục, rồi tăng lên 1.350 lúc 11:22 (có thể là lúc đợt tấn công tiếp theo bắt đầu).
- BENIGN rải đều suốt thời gian, khoảng 24–347 flow mỗi phút.
- Nhận xét từ hình `buoc2_theo_thoi_gian.png`: đợt tấn công có tăng vọt đột ngột ở 11:06 và dừng ở 11:16, BENIGN có thay đổi nhưng không đáng kể trong lúc tấn công, tức là trông vẫn như những khoảng thời gian khác.

## Hướng luồng

- 99,98% flow tấn công là **một chiều** (Total Backward Packets = 0), so với 25,3% ở BENIGN.
- Phù hợp với việc dữ liệu được ghi ở phía nạn nhân: nạn nhân chỉ nhận gói, không phản hồi.

## Đặc trưng nổi bật

Lưu lượng tấn công **cực kỳ đồng nhất**: P5, trung vị và P95 gần như bằng nhau ở hầu hết đặc trưng.

| Đặc trưng | BENIGN (trung vị) | DrDoS_DNS (trung vị) | DrDoS_DNS (P5–P95) |
|---|---|---|---|
| Total Fwd Packets | 2 | 2 | 2–2 |
| Total Backward Packets | 2 | 0 | 0–0 |
| Fwd Packet Length Max | 31 | 1.472 | 465–1.472 |
| Total Length of Fwd Packets | 62 | 2.944 | 1.000–2.944 |
| Flow Duration (µs) | 20.810 | 1 | 1–48 |
| Flow Bytes/s | 1.884 | 2,944 × 10⁹ | 6,0 × 10⁷ – 2,944 × 10⁹ |
| Flow Packets/s | 192 | 2 × 10⁶ | 41.667 – 2 × 10⁶ |
| Flow IAT Mean (µs) | 6.919 | 1 | 1–48 |

- Một flow tấn công điển hình: **2 gói, mỗi gói 1.472 byte, cách nhau 1 µs, không có phản hồi**. 1.472 byte là kích thước payload UDP lớn nhất vừa một khung Ethernet 1.500 byte (1.500 − 20 byte header IP − 8 byte header UDP).
- **Tách rõ BENIGN và tấn công:** các đặc trưng kích thước gói (Fwd Packet Length Max/Mean, Packet Length Mean, Average Packet Size, Total Length of Fwd Packets), các đặc trưng thời gian (Flow Duration, Flow IAT Mean) và Total Backward Packets. P5 của tấn công (465 byte) cao hơn cả P95 của BENIGN (124 byte) ở Fwd Packet Length Mean.
- **Gần như trùng nhau:** Total Fwd Packets (trung vị đều bằng 2).
- **Bất thường:** Average Packet Size của tấn công là 2.208, trong khi Packet Length Mean là 1.472. Hai cột này lẽ ra phải gần bằng nhau (2.208 = 1.472 × 1,5). Đây là lỗi công thức đã biết của CICFlowMeter.
- Nhận xét từ hình `buoc2_phan_phoi_dac_trung.png`: 
  - **Nhóm kích thước gói tách lớp gần như hoàn toàn.** Ở Total Length of Fwd Packets, Fwd Packet Length Max/Mean, Packet Length Mean và Average Packet Size, tấn công chỉ là một cột nhọn duy nhất (khoảng 10^3,2 ≈ 1.472 byte; 10^3,5 ≈ 2.944 byte với tổng độ dài; 10^3,3 ≈ 2.208 byte với Average Packet Size). BENIGN trải rộng trong khoảng 10^1,3–10^2,7 (khoảng 20–500 byte), gần như không chồng lên cột tấn công.
  - **Nhóm tốc độ tách tốt nhưng có chồng lấn.** Flow Bytes/s của tấn công nằm ở 10^7,5–10^9,4, còn BENIGN tập trung quanh 10^4. Flow Packets/s của tấn công tập trung ở 10^4,6, 10^6 và 10^6,3, nhưng một phần nhỏ BENIGN cũng có giá trị khoảng 10^6,3 (các flow BENIGN rất ngắn).
  - **Nhóm thời gian chồng lấn ở đầu thấp.** Flow Duration và Flow IAT Mean của tấn công dồn ở khoảng 1–2 µs và khoảng 48 µs (10^1,7). BENIGN chủ yếu ở 10^4–10^8 µs, nhưng cũng có một phần ở mức 1 µs, nên riêng nhóm này không đủ để phân biệt.
  - **Total Fwd Packets gần như vô dụng:** cả hai lớp đều tập trung ở 2 gói.

## Hệ quả cho Bước 3

1. **Khử trùng lặp trước khi chia tập.** 97,7% dòng trùng; sau khử trùng còn khoảng 116 nghìn vector. Báo cáo cả số liệu trước và sau.
2. **Bỏ cột định danh** khi huấn luyện: Flow ID, Source/Destination IP, Source/Destination Port, Timestamp. Riêng cột IP đã đủ phân biệt hoàn toàn hai lớp.
3. **Bỏ cột thừa:** 12 cột hằng số và `Fwd Header Length.1`.
4. **Xử lý cột lỗi tràn số:** Fwd Header Length, min_seg_size_forward, Bwd Header Length. Có thể bỏ hẳn (an toàn nhất), hoặc giữ nhưng thêm cờ "giá trị âm".
5. **Xử lý Init_Win_bytes = −1:** đây là giá trị hợp lệ nghĩa là "không áp dụng", không phải lỗi. Lưu ý cột này gián tiếp mã hóa giao thức (UDP luôn −1).
6. **Xử lý inf** ở Flow Bytes/s và Flow Packets/s (khi Flow Duration = 0): thay bằng giá trị hữu hạn lớn nhất, hoặc thay bằng null kèm cờ.
7. **Làm sạch nhãn (phương án so sánh):** tách riêng 1.496 dòng DrDoS_DNS không phải UDP và 1.950 dòng chiều ngược (192.168.50.1 → 172.16.0.5), vì có thể là lưu lượng bình thường bị gán nhãn tấn công. Huấn luyện có và không có các dòng này để so sánh.
8. **Chia theo thời gian** dựa trên đợt tấn công thật 11:06–11:16, không phải khung UNB.
9. **Kỳ vọng kết quả:** bài toán DNS so với BENIGN gần như chắc chắn rất dễ (kích thước gói gần như tách hoàn toàn hai lớp), điểm số có thể gần 100%. Giá trị của đề tài nằm ở: đánh giá trung thực (khử trùng, không rò rỉ), thí nghiệm tổng quát hóa sang giao thức khác, và phân tích hạn chế của dữ liệu.

## Phát hiện cần đưa vào báo cáo (mục hạn chế của dữ liệu)

- Lưu lượng tấn công không mang dấu hiệu của DNS reflection thật: một IP nguồn duy nhất, không dùng cổng 53.
- Lịch tấn công UNB công bố lệch khoảng 14 phút so với dữ liệu thực tế.
- 97,7% dòng trùng lặp; nhiều cột lỗi tràn số hoặc lỗi công thức của CICFlowMeter.
- Một phần nhãn tấn công có thể sai (lưu lượng TCP và chiều ngược).