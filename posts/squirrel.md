+++
date = '2025-04-16T03:39:19+07:00'
draft = true
title = 'squ1rrel CTF 2025'
+++


squ1rrel là một giải khá ít challenge rev, chỉ có 3 bài. Mình tham gia giải này song song Breach nên cũng chỉ kịp đóng góp cho team 1 bài.

## Intermediate Software Design - reverse engineering


### 1. Static Analysis
Chương trình chỉ gồm có duy nhất 1 hàm main, nhận input và xử lý nó. Logic xử lý của chương trình lại không quá phức tạp, nó chủ yếu nằm ở đoạn sau.

![](http://note.bksec.vn/pad/uploads/66b44fb3-d5e2-4ab1-b324-6345a6894b6a.png)

Có một lưu ý nhỏ ở đây, chương trình đọc input thành một mảng các ký tự, mỗi ký tự là 4 byte. Ở vòng lặp đầu tiên, con trỏ v3 di chuyển dọc theo mảng ký tự input, rồi lấy kết quả thực hiện xor với kết quả trong &v23.Tuy nhiên, con trỏ v3 lại là con trỏ (_DWORD), mà mảng ký tự đọc vào là các mảng ký tự 4 byte nên phép xor này chỉ ảnh hưởng đến các ký tự lẻ. Chúng ta có thể thấy rõ như sau.

![](http://note.bksec.vn/pad/uploads/46c7f311-3360-4fbd-a8de-8620680e2fda.png)


![](http://note.bksec.vn/pad/uploads/9891d81b-3a03-4eb9-81c9-765ca589c861.png)

Như vậy sau loop thứ nhất sẽ thực hiện phép xor giữa các phần tử lẻ của chuỗi và constant tại &v23.

Ở vòng lặp thứ 2, chương trình lặp qua string sau khi bị biến đổi và thực hiện phép toán vs các constant được lưu sẵn.

![](http://note.bksec.vn/pad/uploads/8e949635-76dd-4756-b763-6504775f5b85.png)

Có một điều đáng lưu ý là v13 là bộ đếm để lấy giá trị tại v21, tuy nhiên v13 cũng chính là bộ đếm ở vòng lặp trên và nó không hề đặt lại về 0 khi vào vòng lặp này nên v13 sẽ bắt đầu từ số phần tử lẻ của input.

Từ phân tích trên, ta chỉ cần lấy constant cần thiết vào và viết script reverse lại là xong.

### 2. Reversing

![](http://note.bksec.vn/pad/uploads/c3ab91dc-5e79-4d62-81db-177bf96fe261.png)

Output chứa ký tự không in được nên mình sẽ lấy giá trị hex ở đây. Đồng thời dễ nhận thấy output có độ dài là 26 nên v13 sẽ bắt đầu từ vị trí 13 ở vòng lặp thứ 2. Mình chạy script reverse và thu được.

![](http://note.bksec.vn/pad/uploads/dd71f5a7-8283-4a51-b955-05ea9bee000c.png)

### 3. Script

```
v21=[3, 3, 1, 5, 50, 8, 1, 9,
 5, 7, 9, 3, 2, 2, 6, 8,
 5, 30, 6, 3, 3, 1, 5, 4,
 8, 1, 9, 5, 7, 2, 3, 2,
 2, 6, 8, 5, 4, 6, 3, 3,
 1, 5, 4, 8, 1, 9, 5, 7,
 9, 3, 2, 2, 6, 8, 5, 4,
 6, 3, 3, 1, 5, 4, 8, 1,
 9, 5, 7, 9, 3, 2, 2, 6,
 8, 5, 4, 6]

n=[0x2a,0x51,0x63,0x4d,0x22,0x5c,0x37,0x7e,0x00]

output='\x59\x75\x2a\x34\x2d\x76\x29\x6d\x58\x7a\x6a\x7a\x73\x6f\x24\x7e\x30\x76\x58\x5f\x26\x5a\x09\x72\x42\x7e'
print(len(output))
res=[]
for i in range(len(output)):
    res.append(ord(output[i])-v21[i+13]+2)
c=[]
for i in range(len(res)):
    if i%2==0:
        c.append(res[i]^n[(i//2)%9])
    else:
        c.append(res[i])
m=''
for i in c:
    m+=chr(i)
print(m)
```
