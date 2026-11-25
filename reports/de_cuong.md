# Đề cương đề tài

## 1. Tên đề tài

**Phát hiện tấn công DDoS phản xạ/khuếch đại DNS bằng học máy trên bộ dữ liệu CIC-DDoS2019**

## 2. Bối cảnh

Trong tấn công DNS reflection/amplification, kẻ tấn công gửi truy vấn DNS nhỏ tới các máy chủ DNS mở (open resolver), với địa chỉ IP nguồn bị giả mạo thành IP của nạn nhân. Các máy chủ DNS gửi phản hồi lớn hơn truy vấn nhiều lần về phía nạn nhân, khiến nạn nhân bị nhấn chìm bởi lưu lượng. Vì kẻ tấn công không trực tiếp gửi lưu lượng tới nạn nhân, việc phát hiện phải dựa vào đặc điểm của lưu lượng đến.

Học máy trên dữ liệu luồng mạng (flow) là hướng tiếp cận phổ biến. Tuy nhiên, nhiều nghiên cứu báo cáo độ chính xác gần 100% trên các bộ dữ liệu như CIC-DDoS2019 mà không xử lý các vấn đề đã biết của dữ liệu: trùng lặp, rò rỉ qua cột định danh, lỗi của công cụ trích xuất đặc trưng. Đề tài này hướng tới một quy trình đánh giá trung thực hơn.

## 3. Mục tiêu

1. Xây dựng quy trình tiền xử lý dữ liệu CIC-DDoS2019 có xử lý trùng lặp, rò rỉ và các lỗi đã biết.
2. Xây dựng và so sánh các mô hình học máy phân loại flow DNS amplification với lưu lượng bình thường (BENIGN).
3. Xác định các đặc trưng flow quyết định khả năng phát hiện.
4. Đánh giá khả năng tổng quát hóa của mô hình sang các giao thức reflection khác.

## 4. Câu hỏi nghiên cứu

- **RQ1.** Sau khi khử trùng lặp và loại bỏ cột định danh, các mô hình học máy phân biệt flow DNS amplification với BENIGN tốt đến mức nào?
- **RQ2.** Những đặc trưng flow nào đóng vai trò quyết định trong việc phát hiện?
- **RQ3.** Mô hình được huấn luyện trên các giao thức reflection khác (LDAP, MSSQL, NetBIOS, NTP, SNMP, SSDP) có phát hiện được tấn công DNS hay không? DNS dễ bị nhầm với giao thức nào nhất?

## 5. Phạm vi

**Trong phạm vi:**
- Phân loại ở mức flow, ngoại tuyến (offline), trên dữ liệu CSV có sẵn.
- Tấn công DNS reflection/amplification so với BENIGN, kèm đánh giá nhầm lẫn với các tấn công reflection khác.

**Ngoài phạm vi:**
- Truy vết nguồn tấn công thật (bất khả thi do giả mạo IP và do dữ liệu được ghi ở phía nạn nhân).
- Phát hiện thời gian thực trên lưu lượng sống hoặc file PCAP.
- Dữ liệu botnet và các kiểu tấn công khai thác (SYN flood, UDP flood, UDP-Lag).

## 6. Dữ liệu

**Nguồn:** CIC-DDoS2019, Canadian Institute for Cybersecurity, University of New Brunswick. Đặc trưng được trích bằng CICFlowMeter-V3 từ lưu lượng ghi ở phía mạng nạn nhân.

**Lựa chọn dữ liệu:** Tấn công DNS chỉ có trong ngày huấn luyện (thư mục 01-12, ngày 01/12/2018), không có trong ngày kiểm tra (03-11). Vì vậy:
- Dữ liệu chính: `DrDoS_DNS.csv` cùng 6 file reflection khác của ngày 01-12 (LDAP, MSSQL, NetBIOS, NTP, SNMP, SSDP). Lớp BENIGN được gom từ tất cả các file.
- `DrDoS_UDP.csv` chỉ dùng để lấy dòng BENIGN, vì UDP flood là tấn công khai thác, không phải phản xạ.
- Ngày 03-11 chỉ dùng để kiểm tra phụ: mô hình có báo nhầm các tấn công khác thành DNS hay không.

**Kết quả khảo sát ban đầu (EDA) trên `DrDoS_DNS.csv`:**

| Chỉ số | Giá trị |
|---|---|
| Tổng số flow | 5.074.413 |
| BENIGN / DrDoS_DNS | 3.402 / 5.071.011 (≈ 1 : 1.490) |
| Số đặc trưng số | 79 |
| Vector đặc trưng khác nhau | 116.331 (97,7% số dòng là trùng lặp) |
| Cột hằng số | 12 |
| Đợt tấn công thực tế | 11:06–11:16 (≈ 99,7% flow tấn công) |

## 7. Phương pháp

**7.1. Tiền xử lý**
- Khử trùng lặp theo vector đặc trưng trước khi chia tập.
- Loại các cột định danh (Flow ID, địa chỉ IP, cổng, Timestamp) để tránh rò rỉ.
- Loại 12 cột hằng số, cột trùng `Fwd Header Length.1`, và các cột bị lỗi tràn số của CICFlowMeter.
- Xử lý giá trị vô cực (Flow Bytes/s, Flow Packets/s) và giá trị −1 của Init_Win_bytes.
- Phương án so sánh: tách các dòng nghi gán nhãn sai (flow tấn công không phải UDP, flow chiều ngược).

**7.2. Chia dữ liệu**
- Chia train/validation/test bên trong ngày 01-12, phân tầng theo nhãn.
- Phương án bổ sung: chia theo thời gian trong đợt tấn công 11:06–11:16.
- Lấy mẫu bớt lớp tấn công chỉ trên tập train; giữ phân bố tự nhiên ở tập test.

**7.3. Mô hình**
- Logistic Regression (đường cơ sở tuyến tính)
- Decision Tree (dễ diễn giải)
- Random Forest
- XGBoost hoặc LightGBM
- (Nếu còn thời gian) Mạng nơ-ron nhiều lớp (MLP)

**7.4. Chỉ số đánh giá**

Do mất cân bằng cực mạnh, không dùng accuracy làm chỉ số chính. Các chỉ số sử dụng: Precision, Recall, F1, tỉ lệ báo động giả (FPR), PR-AUC và ma trận nhầm lẫn.

**7.5. Thí nghiệm**
1. **So sánh mô hình** (RQ1): trên dữ liệu đã khử trùng, so với chưa khử trùng để định lượng mức thổi phồng điểm số.
2. **Phân tích đặc trưng** (RQ2): feature importance, kết hợp ablation bỏ nhóm đặc trưng kích thước gói.
3. **Tổng quát hóa** (RQ3): leave-one-protocol-out, tức huấn luyện trên 6 giao thức reflection khác rồi kiểm tra trên DNS; kiểm tra phụ trên ngày 03-11.

## 8. Kết quả dự kiến

- Quy trình tiền xử lý và đánh giá có thể tái lập (mã nguồn trên Git).
- Bảng so sánh các mô hình, kèm mức chênh lệch điểm số trước và sau khi khử trùng lặp.
- Danh sách đặc trưng quan trọng và giải thích.
- Đánh giá khả năng tổng quát hóa sang giao thức khác.
- Phân tích hạn chế của bộ dữ liệu CIC-DDoS2019 đối với bài toán DNS amplification.

## 9. Hạn chế đã biết

- **Lưu lượng tấn công không mang dấu hiệu DNS reflection thật:** toàn bộ đến từ một địa chỉ IP duy nhất (172.16.0.5), không dùng cổng nguồn 53, cổng đích ngẫu nhiên. Mô hình có thể học đặc điểm của công cụ mô phỏng hơn là của tấn công thật.
- **Bài toán có thể quá dễ:** flow tấn công điển hình gồm 2 gói 1.472 byte cách nhau 1 µs, khác biệt rõ rệt với BENIGN. Điểm số cao chưa chắc phản ánh hiệu quả ngoài thực tế.
- **Lịch tấn công công bố không khớp dữ liệu:** UNB ghi 10:52–11:05, thực tế đợt tấn công nằm ở 11:06–11:16.
- **Lỗi của CICFlowMeter:** giá trị âm do tràn số, cột trùng, công thức Average Packet Size không nhất quán.
- **Một phần nhãn có thể sai:** 1.496 flow mang nhãn DNS nhưng không phải UDP.
- **Mất cân bằng cực mạnh,** với rất ít mẫu BENIGN (khoảng 27,5 nghìn dòng trên toàn bộ 8 file).
- **Dữ liệu ghi ở phía nạn nhân:** không thấy truy vấn của kẻ tấn công, không truy vết được nguồn thật.

## 10. Kế hoạch và mốc

| Tuần | Thời gian | Nội dung | Mốc |
|---|---|---|---|
| 7 | 23–29/11/2026 | Chuẩn bị dữ liệu, EDA, đề cương | **Mốc 1** (29/11) |
| 8 | 30/11–06/12 | Tiền xử lý, chọn đặc trưng | |
| 9 | 07–13/12 | Huấn luyện, so sánh mô hình | **Mốc 2** (13/12) |
| 10 | 14–20/12 | Thí nghiệm tổng quát hóa | |
| 11 | 21–27/12 | Phân tích kết quả, viết báo cáo | |
| 12 | 28/12/2026–03/01/2027 | Hoàn thiện báo cáo, slide | **Mốc 3** (03/01/2027) |

## 11. Cấu trúc báo cáo dự kiến

1. Giới thiệu
2. Cơ sở lý thuyết: DDoS, tấn công phản xạ/khuếch đại DNS, phát hiện xâm nhập dựa trên flow, các mô hình học máy
3. Dữ liệu và khảo sát dữ liệu
4. Phương pháp
5. Kết quả thực nghiệm
6. Thảo luận và hạn chế (kèm các biện pháp phòng thủ: BCP38/uRPF, Response Rate Limiting, đóng open resolver)
7. Kết luận và hướng phát triển

## 12. Tài liệu tham khảo chính

1. I. Sharafaldin, A. H. Lashkari, S. Hakak, A. A. Ghorbani, "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy," *IEEE International Carnahan Conference on Security Technology (ICCST)*, 2019.
2. C. Rossow, "Amplification Hell: Revisiting Network Protocols for DDoS Abuse," *Network and Distributed System Security Symposium (NDSS)*, 2014.
3. G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study," *IEEE Security and Privacy Workshops (SPW)*, 2021.
4. P. Ferguson, D. Senie, "Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing," RFC 2827 (BCP 38), 2000.
5. Canadian Institute for Cybersecurity, "DDoS Evaluation Dataset (CIC-DDoS2019)," https://www.unb.ca/cic/datasets/ddos-2019.html