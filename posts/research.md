+++
date = '2025-04-16T03:43:12+07:00'
draft = true
title = 'Research: Packing và Unpacking trong reverse engineering'
+++


> SLIDE bài thuyết trình: https://www.canva.com/design/DAGiMR6Qp0U/OkIupXHYFkij3xmruojTrQ/edit?utm_content=DAGiMR6Qp0U&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton

Packing là một trong những kỹ thuật cơ bản về bảo vệ file. Đối với các reverser, unpacking là công cụ đắc lực để vượt qua kỹ thuật anti-reverse khá mạnh mẽ này. Hầu hết mọi thứ về phương pháp phân tích thì đều có ở trong slide trên, bài viết này của mình sẽ chỉ tóm tắt lại ý chính từ bài thuyết trình.

## 1. Tổng quan về packing và unpacking.

- Packing: Việc nén, che giấu mã thực thi gốc của chương trình.
- Packer: Chương trình packing file thực thi nhằm che giấu mã thực thi gốc.

Packed File:
-  File thực thi mà mã thực thi gốc đã bị pack bởi packer - nghĩa là mã thực thi gốc đã bị ẩn đi khi load vào các trình disassembler để
phân tích và lưu lại.
- Được packing bằng các kỹ thuật như nén, mã hóa, tự động bổ sung một hoặc nhiều section và đoạn unpacking stub, cuối cùng là packed data. Mã thực thi gốc của chương trình nằm trong packed data.


Mục đích của việc pack các file thực thi: Như các kỹ thuật obfuscating khác, việc pack file thực thi nhằm gây khó khăn hơn đối với các reverser trong việc phân tích và đảo ngược chương trình.Đối với malware, việc pack file khiến cho các trình Anti-virus (AV) khó khăn trong việc xác định nó. Các AV thông thường sẽ quét tuyến tính file PE từ đầu đến cuối của file theo cấu trúc file. Tuy nhiên việc pack đã chèn thêm nhiều section ''rác'', các section rác này bị AV nhận diện là vô hại. Mã thực thi gốc có hại lại nằm bên trong Packed Data. Dữ liệu bên trong Packed Data chỉ bị giải nén khi chương trình được khởi chạy (runtime).

## 2. Nguyên lý hoạt động của packing

- Khi file bị packed, các giá trị bên trong các section sẽ bị nén, mã hóa để che giấu khỏi reverser.
- Packer sẽ thêm các unpacking stub và các section rác vào. Các unpacking stub sẽ khôi phục lại mã thực thi gốc, trạng thái các thanh ghi và dẫn luồng chương trình đến Original entry point của phần mã thực thi đó.
- Khi chương trình thực thi, sau khi load xong hết các phần ở trên thì Instruction Pointer sẽ nhảy đến entry point của chương trình nằm trong Unpacking stub. Các unpacking stub này có nhiệm vụ khôi phục lại mã thực thi gốc, khôi phục lại trạng thái các thanh ghi. Sau khi giải mã/ giải nén mã thực thi gốc xong, trong unpacking stub sẽ có lệnh chuyển hướng vào original entry point (OEP) của đoạn mã thực thi được giải nén.
- Sau đó, chương trình nhảy đến Original Entry Point của vùng mã được giải nén, khôi phục giá trị các thanh ghi (nếu có) và thực thi chương trình như bình thường.

## 3. Phương pháp phân tích và unpack file bị nén

> Nội dung phần này và toàn bộ Demo mình đã trình bày rõ trong slide bên trên.