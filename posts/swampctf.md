+++
date = '2025-04-16T03:23:19+07:00'
draft = true
title = 'SwampCTF 2025'
+++


Đây là một giải có thể nói đặc biệt vì đa phần các chall reversing của nó đều quá tricky mà không yêu cầu nhiều về khả năng logic dịch ngược. 

## Midi Melody - rev


### 1. Static Analysis

![](http://note.bksec.vn/pad/uploads/8cb293a8-061e-479a-ab0f-ba25189f7dd0.png)

Chương trình là một phần mềm sinh ra file midi từ các input đầu vào. Khi khởi chạy cần có tham số dòng lệnh.

![](http://note.bksec.vn/pad/uploads/ce6e6738-0250-4be2-9b91-8ff4183d9fc3.png)

![](http://note.bksec.vn/pad/uploads/917d6e4e-3152-4aac-855b-1945d81e1526.png)

Chương trình sẽ lấy các giá trị tham số từ tham số thứ 2 trở đi, dựa vào giá trị của từng tham số mà thực hiện thao tác với các mảng v13, v14.

Ứng với mỗi giá trị m,j,d; chương trình sẽ đẩy tương ứng một giá trị của mảng v13 và mảng v14 tương ứng vào một vùng nhớ cấp phát động v12.

![](http://note.bksec.vn/pad/uploads/385b5966-b0a0-416e-a18a-48d4580dc1cc.png)

Cuối cùng chương trình ghi lần lượt các giá trị ptr, giá trị trong mảng cấp phát động v12 và giá trị v15 vào file audio.midi. Như vậy phương án của chúng ta là reversing chương trình tìm lại flag ban đầu.

### 2. Reverse

Chúng ta đã biết rằng phần đầu tiên của file midi sẽ là giá trị ptr, phần cuối của file midi sẽ là v15. Vì vậy, mình sẽ bỏ hai phần này và tách phần ở giữa, nơi chứa các giá trị để chuyển thành flag ban đầu.

```
def parse_midi(data):
    header_size = 0x16  
    track_data = data[header_size:-4]  
    extracted_values = [struct.unpack("<I", track_data[i:i+4])[0] for i in range(0, len(track_data), 4)]
    return extracted_values
```

Dựa vào logic ghi dữ liệu vào file audio.midi từ chương trình midiGEN, mình đảo ngược nó để so khớp với các flag.

Đối với '-j':
```
expected_j = v13[v4 % 10]
if note_val == expected_j:
    flags.append("-j")
    v4 += 1
    continue

```
Đối với "-m":
```
expected_normal = v14[v4 % 22]
if note_val == expected_normal:
    flags.append("-m")
    v4 += 1

```
Đối với "-r":
```
elif note_val == v14[0]:
    flags.append("-r")
    v4 = 1  # Reset lại bộ đếm

```


Kết quả flag thu được là:

![](http://note.bksec.vn/pad/uploads/10fcd559-d714-42ac-ad99-404f72d99cde.png)

Lưu ý rằng, chương trình sẽ chỉ đọc từ tham số thứ 2, do vậy thêm 1 trong 3 flag '-m','-j','-r' ở tham số đầu tiên thì đều tạo ra 1 file như nhau. Mình sẽ thử với cả 3 TH này. Tuy nhiên trước hết, chúng ta để ý ở phần help:
![](http://note.bksec.vn/pad/uploads/9486095e-3e62-4bf9-82d5-6bf07e45c867.png)

'-m' kí hiệu là '-'
'-j' kí hiêu là '.'
'-r' kí hiệu là ' '

mình thử thay vào thì được chuỗi 
```.. .-- .- -- .--. -.-. - ..-.  -- .---- -.. .---- -....- .-- .- ... -. - -....- - .... .- - -....- .... .--.-. .-. -..```
Chuỗi này mình tra thì biết được nó là mã Morse (:v), tuy nhiên như đã nói ở trên đây là kết quả sinh ra từ tham số thứ 2 trở đi, do vậy mình đã thử cả 3 TH tham số đầu tiên để giải mã Morse và thu được.

![](http://note.bksec.vn/pad/uploads/0a28bb46-3b61-400c-906a-00b888bb27f6.png)


### 3. Script
```
#!/usr/bin/env python3
import struct
import os

v14 = [
    1614843904, 1614843994, 1614839824, 1614843994, 1614581882, 1614843994,
    1615040634, 1615036538, 1614254202, 1615036538, 1615368314, 1615036506,
    1614254202, 1615036506, 1614057594, 1615036506, 1614385274, 1614516346,
    1614450810, 1614385226, 1615036506, 8106106
]
v13 = [
    1615499264, 1615368276, 1615499348, 1615171711, 1615040639,
    1615499264, 1615368276, 1615499348, 1615171711, 1615040639
]

HEADER_SIZE = 22  
FOOTER_SIZE = 4  

def read_int32_le(b):
    return struct.unpack("<I", b)[0]

def reverse_audio_midi(filename="audio.midi"):
    with open(filename, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE + FOOTER_SIZE:
        print("File quá nhỏ để chứa dữ liệu hợp lệ.")
        return

    header = data[:HEADER_SIZE]
    footer = data[-FOOTER_SIZE:]
    note_data = data[HEADER_SIZE:-FOOTER_SIZE]

    note_count = len(note_data) // 4
    print(f"Đã đọc được {note_count} lệnh ghi (note) từ file.")

    expected_footer = 3145472
    footer_val = read_int32_le(footer)
    if footer_val != expected_footer:
        print(f"Cảnh báo: Footer không khớp (được ghi {footer_val}, mong đợi {expected_footer}).")
    else:
        print("Footer hợp lệ.")
    v4 = 0
    flags = [] 
    
    for i in range(note_count):
        note_bytes = note_data[i*4:(i+1)*4]
        note_val = read_int32_le(note_bytes)

     
        expected_j = v13[v4 % 10]
        if note_val == expected_j:
            flags.append("-j")
            v4 += 1
            continue

        
        expected_normal = v14[v4 % 22]
        if note_val == expected_normal:
           
            flags.append("-m")
            v4 += 1
        elif note_val == v14[0]:
           
            flags.append("-r")
            v4 = 1  
        else:
            print(f"Không nhận dạng được note thứ {i+1}: giá trị = {note_val}")
            flags.append("UNKNOWN")
           

    print("\nChuỗi flag phục hồi (tương ứng argv[2:]):")
    print(" ".join(flags))

if __name__ == "__main__":
 
    import sys
    filename = sys.argv[1] if len(sys.argv) > 1 else "audio.midi"
    if not os.path.exists(filename):
        print(f"Không tìm thấy file {filename}")
    else:
        reverse_audio_midi(filename)

```