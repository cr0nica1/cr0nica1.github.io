+++
date = '2025-04-16T03:30:40+07:00'
draft = true
title = 'Breach CTF 2025'
+++

Breach có lẽ là giải khá khó chịu với mình vì không có nhiều chall thuần về reversing logic và xác định luồng truyền thống, mặt khác nó lại có phần tricky ở nhiều chall. Ở giải này chỉ có mình mình giải 1 chall.

## Fraction Fun - rev

### 1. Analysis

Chall cho biết file mã nguồn của chương trình xác thực trên server. Cần phải nhập chính xác số cần nhập để sau các phép biến đổi, kết quả sẽ bằng kết quả trong output.txt. Logic chương trình khá đơn giản, chỉ là vòng lặp sau. 

```
for _ in range(1000):
    changed = False
    for i in range(len(a)):
        if inp % b[i] == 0:
            inp = inp * a[i] // b[i]
            changed = True
    if not changed:
        broken = True
        break
```

Đối với đoạn logic đơn giản này, chúng ta chỉ đơn giản là viết script đảo ngược phép logic này là được.

### 2. Reversing

Đoạn mã đảo ngược logic dễ dàng đạt được bằng cách thực hiện ngược lại các phép toán biến đổi trên:

```
for _ in range(1000):
        changed = False
        
        for i in reversed(range(len(a))):
            ai = a[i]
            bi = b[i]
            if current % ai == 0:
                current = current * bi // ai
                changed = True
        if not changed:
            broken = True
            break
```

Sử dụng đoạn mã này vào script thu được.
![](http://note.bksec.vn/pad/uploads/eee7406e-d6a6-4bd6-83c3-8246657e07cb.png)

Nhập vào và lấy flag.
![](http://note.bksec.vn/pad/uploads/f7876a35-a704-47bd-93bc-597c34fd3043.png)


### 3. Script

```
def reverse_execute(code, fin_output):
    values = code.split(" ")
    a = [int(i.split("/")[0]) for i in values]
    b = [int(i.split("/")[1]) for i in values]
    current = fin_output
    broken = False
    for _ in range(1000):
        changed = False
        
        for i in reversed(range(len(a))):
            ai = a[i]
            bi = b[i]
            if current % ai == 0:
                current = current * bi // ai
                changed = True
        if not changed:
            broken = True
            break
    if not broken:
        print("Reverse loop did not terminate in 1000 iterations!")
    return current

code = open("code.txt", "r").read().strip()
fin_output = int(open("output.txt", "r").read().strip())

required_input = reverse_execute(code, fin_output)
print(required_input)
```