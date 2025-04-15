+++
date = '2025-04-16T03:10:02+07:00'
draft = true
title = 'Hackthebox: Cyber Apocalypse CTF 2025: Tales from Eldoria'
+++

Như mọi khi, hackthebox luôn mang đến cho chúng ta giải CTF khá chất lượng về độ phân loại, phù hợp cho cả beginner và người đã có kinh nghiệm. Ở giải này những challenge easy và very easy đều quá dễ nên mình sẽ chỉ viết writeup challenge mức độ medium mình giải được.

# Writeup

## Singlestep - rev

### 1. Static Analysis

Load file vào IDA, chúng ta nhận thấy hàm hàm main call đến một hàm loc_5555555583E0 nào đấy. Vào trong hàm bên trong hàm này kiểm tra.

![](http://note.bksec.vn/pad/uploads/611c44ee-d31b-48bd-a3fa-0b72f43c105f.png)

Ở bên trong này, chúng ta thấy một đoạn dài mã thực thi thuộc section .text mà IDA không đọc được code x64 asm. Nhìn vào các lệnh xor, mình nhận ra rằng chương trình sẽ giải mã các vùng mã không đọc được đó bằng xor, thực thi lệnh ở đó rồi lại xor lại để mã hóa 1 lần nữa. Do vậy đoạn mã này chỉ có thể đọc được trong runtime, không thể đọc được bằng cách disassemble thông thường. Cách duy nhất mình nghĩ được là lưu lại code được giải mã trong khi debug, tuy nhiên sẽ rất mất thời gian nên mình phải sử dụng script (được tài trợ bởi anh shynt_ :v) để lưu lại những đoạn code được deobfucasting trong khi chạy. Do mình quan tâm đến đoạn code từ sau khi nhập input nên mình sẽ deobfuscating kể từ đoạn yêu cầu nhập input. Lưu ý rằng trong tất cả các string được in ra màn hình, chỉ có duy nhất 1 string gọi printf là "Please enter the ✨ secret ✨ bequeathed to his cult following:", do vậy script sẽ deobfuscating từ printf trong got.plt.


```
import gdb

gdb.execute("file singlestep")
gdb.execute("break printf@plt")
gdb.execute("run")

log_file = open("log.txt", "w")

try:
    while True:
        gdb.execute("stepi", to_string=True)
        output = gdb.execute("x/i $pc", to_string=True)
        
        if "xor" in output and ("BYTE" in output or "WORD" in output or "DWORD" in output):
            continue

        if "nop" in output:
            continue

        if "pushfq" in output:
            continue

        if "popfq" in output:
            continue

        if "pushf" in output:
            continue

        if "popf" in output:
            continue

        
        # print(output.strip())
        log_file.write(output)
        log_file.flush()
except KeyboardInterrupt:
    print("")
finally:
    log_file.close()
```

### 2. Dynamic analysis

Đặt breakpoint tại điểm đầu tiên của đoạn code được ghi lại bởi script trên. Tiếp tục sử dụng step into cho đến khi chương trình đọc input, nhập input rồi dừng lại.

![](http://note.bksec.vn/pad/uploads/950ceb83-4dab-4a20-958b-7e6b29dfef1c.png)

Mình vào file log.txt, cắt script kể từ đoạn này cho đến khi chương trình gọi lệnh puts. Đây sẽ là phần logic chính của chương trình. 

```
=> 0x55555555b0a2:	mov    DWORD PTR [rbp-0x27c],eax
=> 0x55555555b0d9:	cmp    DWORD PTR [rbp-0x27c],0x0
    → cmp operands: DWORD PTR [rbp-0x27c] = N/A, 0x0 = 0
=> 0x55555555b111:	js     0x55555555b2ba

=> 0x55555555b141:	mov    eax,DWORD PTR [rbp-0x27c]
=> 0x55555555b16e:	sub    eax,0x1
=> 0x55555555b18e:	cdqe
=> 0x55555555b1b1:	movzx  eax,BYTE PTR [rbp+rax*1-0x210]
=> 0x55555555b1da:	cmp    al,0xa
    → cmp operands: $al = 10, 0xa = 10
=> 0x55555555b1fc:	jne    0x55555555b2ba

=> 0x55555555b22c:	mov    eax,DWORD PTR [rbp-0x27c]
=> 0x55555555b259:	sub    eax,0x1
=> 0x55555555b279:	cdqe
=> 0x55555555b29c:	mov    BYTE PTR [rbp+rax*1-0x210],0x0
=> 0x55555555b2d6:	lea    rax,[rbp-0x210]
=> 0x55555555b30b:	mov    rdi,rax
=> 0x55555555b333:	call   0x555555557690
```

Đọc đoạn asm này kết hợp với debug, chúng ta dễ dàng nhận ra chương trình loại bỏ ký tự "/n" cuối cùng từ input, sau đó lưu lại giá trị này lên stack. Cuối đoạn mã này, chương trình đẩy địa chỉ của vùng nhớ chứa chuỗi input vào rdi.


```
=> 0x55555555769c:	endbr64                            // kiem tra do dai input
=> 0x5555555576b5:	push   rbp
=> 0x5555555576d1:	mov    rbp,rsp
=> 0x5555555576f2:	sub    rsp,0x18
=> 0x55555555770e:	mov    QWORD PTR [rbp-0x18],rdi
=> 0x555555557734:	mov    QWORD PTR [rbp-0x8],0x0
=> 0x555555557765:	jmp    0x5555555577d0
=> 0x5555555577dc:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x5555555577fe:	movzx  eax,BYTE PTR [rax]
=> 0x55555555781e:	test   al,al
=> 0x555555557840:	jne    0x55555555777a

=> 0x55555555778d:	add    QWORD PTR [rbp-0x8],0x1
=> 0x5555555577b8:	add    QWORD PTR [rbp-0x18],0x1
=> 0x5555555577dc:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x5555555577fe:	movzx  eax,BYTE PTR [rax]
=> 0x55555555781e:	test   al,al
=> 0x555555557840:	jne    0x55555555777a
```

Chương trình bắt đầu call một hàm, bên trong hàm này chương trình duyệt qua các ký tự của string và cập nhật kết quả độ dài của string. Khi vòng lặp kết thúc, chương trình lưu giá trị biến đếm vào rax và thoát khỏi hàm, sau đó so sánh độ dài string với 0x13.
```
=> 0x555555557867:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555557880:	leave
=> 0x55555555788a:	ret


=> 0x55555555b357:	cmp    rax,0x13               // kiem tra do dai string.
    → cmp operands: $rax = 19, 0x13 = 19
```

Nếu như độ dài string input thỏa mãn độ dài 19, rip của chương trình nhảy tiếp vào đoạn mã sau:

```
=> 0x55555555b37c:	je     0x55555555b418                                       // loop kiem tra dieu kien dau tien
=> 0x55555555b437:	mov    DWORD PTR [rbp-0x294],0x0
=> 0x55555555b47c:	mov    BYTE PTR [rbp-0x296],0x1
=> 0x55555555b4be:	mov    DWORD PTR [rbp-0x290],0x0
=> 0x55555555b4fa:	jmp    0x55555555bd54
=> 0x55555555bd70:	cmp    DWORD PTR [rbp-0x290],0x12
    → cmp operands: DWORD PTR [rbp-0x290] = N/A, 0x12 = 18
=> 0x55555555bda8:	jle    0x55555555b512

=> 0x55555555b527:	mov    edx,DWORD PTR [rbp-0x290]
=> 0x55555555b554:	movsxd rax,edx
=> 0x55555555b585:	imul   rax,rax,0x66666667
=> 0x55555555b5b4:	shr    rax,0x20
=> 0x55555555b5cf:	sar    eax,1
=> 0x55555555b5e7:	mov    ecx,edx
=> 0x55555555b606:	sar    ecx,0x1f
=> 0x55555555b626:	sub    eax,ecx
=> 0x55555555b63e:	mov    ecx,eax
=> 0x55555555b65d:	shl    ecx,0x2
=> 0x55555555b67d:	add    ecx,eax
=> 0x55555555b695:	mov    eax,edx
=> 0x55555555b6ad:	sub    eax,ecx
=> 0x55555555b6cc:	cmp    eax,0x4
    → cmp operands: $eax = 0, 0x4 = 4
=> 0x55555555b6f6:	jne    0x55555555b8e4
=> 0x55555555b8f9:	mov    eax,DWORD PTR [rbp-0x294]
=> 0x55555555b926:	lea    edx,[rax+0x1]
=> 0x55555555b950:	mov    DWORD PTR [rbp-0x294],edx
=> 0x55555555b980:	mov    edx,DWORD PTR [rbp-0x290]
=> 0x55555555b9ad:	movsxd rdx,edx
=> 0x55555555b9d8:	movzx  edx,BYTE PTR [rbp+rdx*1-0x210]
=> 0x55555555ba01:	cdqe
=> 0x55555555ba2a:	mov    BYTE PTR [rbp+rax*1-0x110],dl
=> 0x55555555ba69:	movzx  edx,BYTE PTR [rbp-0x296]
=> 0x55555555baa1:	mov    eax,DWORD PTR [rbp-0x290]
=> 0x55555555bac7:	cdqe
=> 0x55555555baea:	movzx  eax,BYTE PTR [rbp+rax*1-0x210]
=> 0x55555555bb13:	cmp    al,0x40
    → cmp operands: $al = 65, 0x40 = 64
=> 0x55555555bb35:	jle    0x55555555bc63
=> 0x55555555bb65:	mov    eax,DWORD PTR [rbp-0x290]
=> 0x55555555bb8b:	cdqe
=> 0x55555555bbae:	movzx  eax,BYTE PTR [rbp+rax*1-0x210]
=> 0x55555555bbd7:	cmp    al,0x5a
    → cmp operands: $al = 65, 0x5a = 90
=> 0x55555555bbf9:	jg     0x55555555bc63
=> 0x55555555bc23:	mov    eax,0x1
=> 0x55555555bc4e:	jmp    0x55555555bc8e
=> 0x55555555bc99:	and    eax,edx
=> 0x55555555bcb1:	test   eax,eax
=> 0x55555555bcd0:	setne  al
=> 0x55555555bcfa:	mov    BYTE PTR [rbp-0x296],al
=> 0x55555555bd31:	add    DWORD PTR [rbp-0x290],0x1
=> 0x55555555bd70:	cmp    DWORD PTR [rbp-0x290],0x12
    → cmp operands: DWORD PTR [rbp-0x290] = N/A, 0x12 = 18
=> 0x55555555bda8:	jle    0x55555555b512
```

Đoạn mã này lặp qua các giá trị của string và kiểm tra điều kiện của mỗi ký tự. Ở các index không chia hết cho 4, chương trình sẽ kiểm tra xem giá trị có nằm trong khoảng từ 0x41 đến 0x5a hay không (các giá trị của ký tự chữ cái in hoa). Đối với trường hợp index chia hết cho 4, chương trình sẽ thực thi kiểm tra xem có phải 0x2d (tức '-') hay không.
```
=> 0x55555555b72d:	movzx  edx,BYTE PTR [rbp-0x296]
=> 0x55555555b765:	mov    eax,DWORD PTR [rbp-0x290]
=> 0x55555555b78b:	cdqe
=> 0x55555555b7ae:	movzx  eax,BYTE PTR [rbp+rax*1-0x210]
=> 0x55555555b7d7:	cmp    al,0x2d
    → cmp operands: $al = 45, 0x2d = 45
```

Tuy nhiên, chương trình chỉ lưu lại các giá trị từ 0x41 đến 0x5a ('A' đến 'Z'). Sau khi loại bỏ hết các ký tự '-' trong string, chương trình tiếp tục duyệt qua từng phần tử một và thực hiện 1 logic biến đổi nào đó.


```
=> 0x55555555bfed:	mov    eax,DWORD PTR [rbp-0x28c]      // loop 1
=> 0x55555555c024:	lea    edx,[rax*4+0x0]
=> 0x55555555c05c:	mov    eax,DWORD PTR [rbp-0x288]
=> 0x55555555c082:	add    eax,edx                               // k=4*i+j
=> 0x55555555c09a:	cdqe
=> 0x55555555c0bd:	movzx  eax,BYTE PTR [rbp+rax*1-0x110]       
=> 0x55555555c0ed:	movsx  eax,al
=> 0x55555555c114:	lea    edx,[rax-0x41]                 // edx=pos(input[k])
=> 0x55555555c13e:	mov    eax,DWORD PTR [rbp-0x28c]
=> 0x55555555c175:	imul   eax,DWORD PTR [rbp-0x288]
=> 0x55555555c1a3:	mov    ecx,eax
=> 0x55555555c1bb:	mov    eax,edx
=> 0x55555555c1d3:	sub    eax,ecx                   
=> 0x55555555c1f2:	movsxd rcx,eax                  //rcx=pos(input[k])-i*j
=> 0x55555555c21c:	mov    eax,DWORD PTR [rbp-0x288]
=> 0x55555555c249:	movsxd rdx,eax
=> 0x55555555c273:	mov    eax,DWORD PTR [rbp-0x28c]
=> 0x55555555c2a0:	movsxd rsi,eax
=> 0x55555555c2d1:	lea    rax,[rbp-0x250]             
=> 0x55555555c306:	mov    rdi,rax                                    
=> 0x55555555c32e:	call   0x555555556180



=> 0x55555555618c:	endbr64
=> 0x5555555561a5:	push   rbp
=> 0x5555555561c1:	mov    rbp,rsp
=> 0x5555555561e2:	sub    rsp,0x30
=> 0x5555555561fe:	mov    QWORD PTR [rbp-0x18],rdi     // 4
=> 0x55555555621a:	mov    QWORD PTR [rbp-0x20],rsi    //  i
=> 0x555555556236:	mov    QWORD PTR [rbp-0x28],rdx    // j
=> 0x555555556252:	mov    QWORD PTR [rbp-0x30],rcx    // pos(input[k])-i*j
=> 0x55555555626e:	mov    rax,QWORD PTR [rbp-0x18]    
=> 0x555555556290:	mov    rax,QWORD PTR [rax]          
=> 0x5555555562b1:	cmp    QWORD PTR [rbp-0x20],rax    // cmp i,4
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x5555555562d6:	jb     0x555555556343
=> 0x55555555634f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555636b:	mov    rax,QWORD PTR [rax+0x8]    
=> 0x555555556387:	cmp    QWORD PTR [rbp-0x28],rax          // cmp j,4
    → cmp operands: [rbp-0x28] = N/A, $rax = 4           
=> 0x5555555563ac:	jb     0x555555556419

=> 0x555555556425:	mov    rax,QWORD PTR [rbp-0x18]    //
=> 0x555555556441:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555556464:	imul   rax,QWORD PTR [rbp-0x20]    
=> 0x55555555648e:	mov    rdx,rax
=> 0x5555555564af:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x5555555564d1:	add    rax,rdx                  
=> 0x5555555564f2:	mov    QWORD PTR [rbp-0x8],rax       // QWORD PTR [rbp-0x8]=k
=> 0x55555555650e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555652a:	mov    rdx,QWORD PTR [rax+0x10]    // rdx=0x555555574a40   # memory 1
=> 0x555555556546:	mov    rax,QWORD PTR [rbp-0x8]   
=> 0x555555556562:	shl    rax,0x3                        // shl 4*i+j,0x3
=> 0x555555556584:	add    rdx,rax
=> 0x5555555565a5:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x5555555565c7:	mov    QWORD PTR [rdx],rax                    // 0x555555574a40+(shl k,0x3) : pos(input[k])-i*j
=> 0x5555555565ef:	mov    eax,0x1
=> 0x555555556610:	leave
=> 0x55555555661a:	ret
=> 0x55555555c362:	add    DWORD PTR [rbp-0x288],0x1                      cap nhat index moi hang
=> 0x55555555c3a1:	cmp    DWORD PTR [rbp-0x288],0x3
    → cmp operands: DWORD PTR [rbp-0x288] = N/A, 0x3 = 3
=> 0x55555555c3d9:	jle    0x55555555bfd8
```

Đoạn mã này tải các đoạn 4 ký tự một và lưu vào 1 địa chỉ, mình dựng lại như sau.
```
k=4*i+j
for(i=0;i<4;i++){
    for(j=0;j<4;j++){
    (QWORD *) (0x555555574a40+k<<0x3)=input[k]-0x41-i*j
    }
}
```

Như vậy chương trình tạo một ma trận 4x4 gồm các giá trị là khoảng cách từ vị trí của ký tự đến 'A' rồi trừ đi i*j. Tiếp tục debug chương trình ta gặp đoạn mã sau.

```
=> 0x55555555c5ff:	call   0x555555556630    /// phep nhan ma tran

=> 0x55555555663c:	endbr64
=> 0x555555556655:	push   rbp
=> 0x555555556671:	mov    rbp,rsp
=> 0x555555556692:	sub    rsp,0x50
=> 0x5555555566ae:	mov    QWORD PTR [rbp-0x38],rdi
=> 0x5555555566ca:	mov    QWORD PTR [rbp-0x40],rsi
=> 0x5555555566e6:	mov    QWORD PTR [rbp-0x48],rdx
=> 0x555555556713:	mov    rax,QWORD PTR fs:0x28
=> 0x555555556745:	mov    QWORD PTR [rbp-0x8],rax
=> 0x555555556779:	mov    rax,QWORD PTR [rbp-0x38]
=> 0x555555556795:	mov    rdx,QWORD PTR [rax+0x8]
=> 0x5555555567b1:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x5555555567d3:	mov    rax,QWORD PTR [rax]
=> 0x5555555567fa:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x555555556824:	je     0x555555556891
=> 0x55555555689d:	mov    rax,QWORD PTR [rbp-0x48]
=> 0x5555555568bf:	mov    rdx,QWORD PTR [rax]
=> 0x5555555568e0:	mov    rax,QWORD PTR [rbp-0x38]
=> 0x555555556902:	mov    rax,QWORD PTR [rax]
=> 0x555555556929:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x555555556953:	jne    0x555555556a31
=> 0x55555555697a:	mov    rax,QWORD PTR [rbp-0x48]
=> 0x555555556996:	mov    rdx,QWORD PTR [rax+0x8]
=> 0x5555555569b2:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x5555555569ce:	mov    rax,QWORD PTR [rax+0x8]
=> 0x5555555569f0:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x555555556a1a:	je     0x555555556a87
=> 0x555555556aa3:	mov    DWORD PTR [rbp-0x2c],0x0
=> 0x555555556ad9:	jmp    0x55555555749f
=> 0x5555555574b1:	mov    eax,DWORD PTR [rbp-0x2c]
=> 0x5555555574d8:	movsxd rdx,eax
=> 0x5555555574f9:	mov    rax,QWORD PTR [rbp-0x38]
=> 0x55555555751b:	mov    rax,QWORD PTR [rax]
=> 0x555555557542:	cmp    rdx,rax
    → cmp operands: $rdx = 0, $rax = 4
=> 0x55555555756c:	jb     0x555555556af1
=> 0x555555556b0d:	mov    DWORD PTR [rbp-0x28],0x0
=> 0x555555556b43:	jmp    0x5555555573a6
=> 0x5555555573b8:	mov    eax,DWORD PTR [rbp-0x28]
=> 0x5555555573df:	movsxd rdx,eax
=> 0x555555557400:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x55555555741c:	mov    rax,QWORD PTR [rax+0x8]
=> 0x55555555743e:	cmp    rdx,rax
    → cmp operands: $rdx = 0, $rax = 4
=> 0x555555557468:	jb     0x555555556b5b
=> 0x555555556b71:	mov    QWORD PTR [rbp-0x10],0x0
=> 0x555555556bab:	mov    DWORD PTR [rbp-0x24],0x0
=> 0x555555556be1:	jmp    0x5555555570bb
=> 0x5555555570cd:	mov    eax,DWORD PTR [rbp-0x24]
=> 0x5555555570f4:	movsxd rdx,eax
=> 0x555555557115:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x555555557137:	mov    rax,QWORD PTR [rax]
=> 0x55555555715e:	cmp    rdx,rax
    → cmp operands: $rdx = 0, $rax = 4
=> 0x555555557188:	jb     0x555555556bf9
=> 0x555555556c0f:	mov    QWORD PTR [rbp-0x20],0x0
=> 0x555555556c43:	mov    QWORD PTR [rbp-0x18],0x0
=> 0x555555556c73:	mov    eax,DWORD PTR [rbp-0x24]
=> 0x555555556c9a:	movsxd rdx,eax
=> 0x555555556cc1:	mov    eax,DWORD PTR [rbp-0x2c]
=> 0x555555556ce8:	movsxd rsi,eax
=> 0x555555556d09:	lea    rcx,[rbp-0x20]
=> 0x555555556d25:	mov    rax,QWORD PTR [rbp-0x38]
=> 0x555555556d47:	mov    rdi,rax

=> 0x555555556d6f:	call   0x555555555ca0

=> 0x555555555cac:	endbr64
=> 0x555555555cc5:	push   rbp
=> 0x555555555ce1:	mov    rbp,rsp
=> 0x555555555d02:	sub    rsp,0x30
=> 0x555555555d1e:	mov    QWORD PTR [rbp-0x18],rdi
=> 0x555555555d3a:	mov    QWORD PTR [rbp-0x20],rsi
=> 0x555555555d56:	mov    QWORD PTR [rbp-0x28],rdx
=> 0x555555555d72:	mov    QWORD PTR [rbp-0x30],rcx
=> 0x555555555d8e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555db0:	mov    rax,QWORD PTR [rax]
=> 0x555555555dd1:	cmp    QWORD PTR [rbp-0x20],rax
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x555555555df6:	jb     0x555555555e63
=> 0x555555555e6f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555e8b:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555ea7:	cmp    QWORD PTR [rbp-0x28],rax
    → cmp operands: [rbp-0x28] = N/A, $rax = 4
=> 0x555555555ecc:	jb     0x555555555f39
=> 0x555555555f45:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555f61:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555f84:	imul   rax,QWORD PTR [rbp-0x20]
=> 0x555555555fae:	mov    rdx,rax
=> 0x555555555fcf:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x555555555ff1:	add    rax,rdx
=> 0x555555556012:	mov    QWORD PTR [rbp-0x8],rax
=> 0x55555555602e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555604a:	mov    rdx,QWORD PTR [rax+0x10]
=> 0x555555556066:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555556082:	shl    rax,0x3
=> 0x5555555560a4:	add    rax,rdx
=> 0x5555555560cb:	mov    rdx,QWORD PTR [rax]
=> 0x5555555560ec:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x55555555610e:	mov    QWORD PTR [rax],rdx
=> 0x555555556136:	mov    eax,0x1
=> 0x555555556157:	leave
=> 0x555555556161:	ret

=> 0x555555556db9:	test   al,al
=> 0x555555556ddb:	je     0x555555556e48
=> 0x555555556e5a:	mov    eax,DWORD PTR [rbp-0x28]
=> 0x555555556e81:	movsxd rdx,eax
=> 0x555555556ea8:	mov    eax,DWORD PTR [rbp-0x24]
=> 0x555555556ecf:	movsxd rsi,eax
=> 0x555555556ef0:	lea    rcx,[rbp-0x18]
=> 0x555555556f0c:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x555555556f2e:	mov    rdi,rax
=> 0x555555556f56:	call   0x555555555ca0
=> 0x555555555cac:	endbr64
=> 0x555555555cc5:	push   rbp
=> 0x555555555ce1:	mov    rbp,rsp
=> 0x555555555d02:	sub    rsp,0x30
=> 0x555555555d1e:	mov    QWORD PTR [rbp-0x18],rdi
=> 0x555555555d3a:	mov    QWORD PTR [rbp-0x20],rsi
=> 0x555555555d56:	mov    QWORD PTR [rbp-0x28],rdx
=> 0x555555555d72:	mov    QWORD PTR [rbp-0x30],rcx
=> 0x555555555d8e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555db0:	mov    rax,QWORD PTR [rax]
=> 0x555555555dd1:	cmp    QWORD PTR [rbp-0x20],rax
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x555555555df6:	jb     0x555555555e63
=> 0x555555555e6f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555e8b:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555ea7:	cmp    QWORD PTR [rbp-0x28],rax
    → cmp operands: [rbp-0x28] = N/A, $rax = 4
=> 0x555555555ecc:	jb     0x555555555f39
=> 0x555555555f45:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555f61:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555f84:	imul   rax,QWORD PTR [rbp-0x20]
=> 0x555555555fae:	mov    rdx,rax
=> 0x555555555fcf:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x555555555ff1:	add    rax,rdx
=> 0x555555556012:	mov    QWORD PTR [rbp-0x8],rax
=> 0x55555555602e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555604a:	mov    rdx,QWORD PTR [rax+0x10]
=> 0x555555556066:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555556082:	shl    rax,0x3
=> 0x5555555560a4:	add    rax,rdx
=> 0x5555555560cb:	mov    rdx,QWORD PTR [rax]
=> 0x5555555560ec:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x55555555610e:	mov    QWORD PTR [rax],rdx
=> 0x555555556136:	mov    eax,0x1
=> 0x555555556157:	leave
=> 0x555555556161:	ret


=> 0x555555555cac:	endbr64
=> 0x555555555cc5:	push   rbp
=> 0x555555555ce1:	mov    rbp,rsp
=> 0x555555555d02:	sub    rsp,0x30
=> 0x555555555d1e:	mov    QWORD PTR [rbp-0x18],rdi
=> 0x555555555d3a:	mov    QWORD PTR [rbp-0x20],rsi
=> 0x555555555d56:	mov    QWORD PTR [rbp-0x28],rdx
=> 0x555555555d72:	mov    QWORD PTR [rbp-0x30],rcx
=> 0x555555555d8e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555db0:	mov    rax,QWORD PTR [rax]
=> 0x555555555dd1:	cmp    QWORD PTR [rbp-0x20],rax
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x555555555df6:	jb     0x555555555e63
=> 0x555555555e6f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555e8b:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555ea7:	cmp    QWORD PTR [rbp-0x28],rax
    → cmp operands: [rbp-0x28] = N/A, $rax = 4
=> 0x555555555ecc:	jb     0x555555555f39
=> 0x555555555f45:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555f61:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555555f84:	imul   rax,QWORD PTR [rbp-0x20]
=> 0x555555555fae:	mov    rdx,rax
=> 0x555555555fcf:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x555555555ff1:	add    rax,rdx
=> 0x555555556012:	mov    QWORD PTR [rbp-0x8],rax
=> 0x55555555602e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555604a:	mov    rdx,QWORD PTR [rax+0x10]
=> 0x555555556066:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555556082:	shl    rax,0x3
=> 0x5555555560a4:	add    rax,rdx
=> 0x5555555560cb:	mov    rdx,QWORD PTR [rax]
=> 0x5555555560ec:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x55555555610e:	mov    QWORD PTR [rax],rdx
=> 0x555555556136:	mov    eax,0x1
=> 0x555555556157:	leave
=> 0x555555556161:	ret

=> 0x555555556db9:	test   al,al
=> 0x555555556ddb:	je     0x555555556e48
=> 0x555555556e5a:	mov    eax,DWORD PTR [rbp-0x28]
=> 0x555555556e81:	movsxd rdx,eax
=> 0x555555556ea8:	mov    eax,DWORD PTR [rbp-0x24]
=> 0x555555556ecf:	movsxd rsi,eax
=> 0x555555556ef0:	lea    rcx,[rbp-0x18]
=> 0x555555556f0c:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x555555556f2e:	mov    rdi,rax
=> 0x555555556f56:	call   0x555555555ca0
...........

=> 0x555555556fa0:	test   al,al
=> 0x555555556fc2:	je     0x55555555702f
=> 0x55555555703b:	mov    rdx,QWORD PTR [rbp-0x20]
=> 0x555555557057:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555557073:	imul   rax,rdx
=> 0x55555555708f:	add    QWORD PTR [rbp-0x10],rax
=> 0x5555555570ab:	add    DWORD PTR [rbp-0x24],0x1
=> 0x5555555570cd:	mov    eax,DWORD PTR [rbp-0x24]
=> 0x5555555570f4:	movsxd rdx,eax
=> 0x555555557115:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x555555557137:	mov    rax,QWORD PTR [rax]
=> 0x55555555715e:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x555555557188:	jb     0x555555556bf9
=> 0x5555555571b5:	mov    eax,DWORD PTR [rbp-0x28]
=> 0x5555555571dc:	movsxd rdx,eax
=> 0x555555557203:	mov    eax,DWORD PTR [rbp-0x2c]
=> 0x55555555722a:	movsxd rsi,eax
=> 0x55555555724b:	mov    rcx,QWORD PTR [rbp-0x10]
=> 0x555555557267:	mov    rax,QWORD PTR [rbp-0x48]
=> 0x555555557289:	mov    rdi,rax
=> 0x5555555572b1:	call   0x555555556180
=> 0x55555555618c:	endbr64
=> 0x5555555561a5:	push   rbp
=> 0x5555555561c1:	mov    rbp,rsp
=> 0x5555555561e2:	sub    rsp,0x30
=> 0x5555555561fe:	mov    QWORD PTR [rbp-0x18],rdi
=> 0x55555555621a:	mov    QWORD PTR [rbp-0x20],rsi
=> 0x555555556236:	mov    QWORD PTR [rbp-0x28],rdx
=> 0x555555556252:	mov    QWORD PTR [rbp-0x30],rcx
=> 0x55555555626e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555556290:	mov    rax,QWORD PTR [rax]
=> 0x5555555562b1:	cmp    QWORD PTR [rbp-0x20],rax
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x5555555562d6:	jb     0x555555556343
=> 0x55555555634f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555636b:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555556387:	cmp    QWORD PTR [rbp-0x28],rax
    → cmp operands: [rbp-0x28] = N/A, $rax = 4
=> 0x5555555563ac:	jb     0x555555556419
=> 0x555555556425:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555556441:	mov    rax,QWORD PTR [rax+0x8]
=> 0x555555556464:	imul   rax,QWORD PTR [rbp-0x20]
=> 0x55555555648e:	mov    rdx,rax
=> 0x5555555564af:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x5555555564d1:	add    rax,rdx
=> 0x5555555564f2:	mov    QWORD PTR [rbp-0x8],rax
=> 0x55555555650e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555652a:	mov    rdx,QWORD PTR [rax+0x10]
=> 0x555555556546:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555556562:	shl    rax,0x3
=> 0x555555556584:	add    rdx,rax
=> 0x5555555565a5:	mov    rax,QWORD PTR [rbp-0x30]
=> 0x5555555565c7:	mov    QWORD PTR [rdx],rax
=> 0x5555555565ef:	mov    eax,0x1
=> 0x555555556610:	leave
=> 0x55555555661a:	ret
=> 0x5555555572fb:	test   al,al
=> 0x55555555731d:	je     0x55555555738a
=> 0x555555557396:	add    DWORD PTR [rbp-0x28],0x1
=> 0x5555555573b8:	mov    eax,DWORD PTR [rbp-0x28]
=> 0x5555555573df:	movsxd rdx,eax
=> 0x555555557400:	mov    rax,QWORD PTR [rbp-0x40]
=> 0x55555555741c:	mov    rax,QWORD PTR [rax+0x8]
=> 0x55555555743e:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x555555557468:	jb     0x555555556b5b
=> 0x55555555748f:	add    DWORD PTR [rbp-0x2c],0x1
=> 0x5555555574b1:	mov    eax,DWORD PTR [rbp-0x2c]
=> 0x5555555574d8:	movsxd rdx,eax
=> 0x5555555574f9:	mov    rax,QWORD PTR [rbp-0x38]
=> 0x55555555751b:	mov    rax,QWORD PTR [rax]
=> 0x555555557542:	cmp    rdx,rax
    → cmp operands: $rdx = 4, $rax = 4
=> 0x55555555756c:	jb     0x555555556af1
=> 0x55555555759a:	mov    eax,0x1
=> 0x5555555575be:	mov    rdx,QWORD PTR [rbp-0x8]
.......
```

Mình đọc đoạn mã này trong text lại khá là dài và cũng không hiểu rõ nó làm gì. Nhờ gợi ý của mọi người nên mình thử một vài input đặc biệt rồi debug, cuối cùng mình đoán được đây là một đoạn mã thực hiện việc nhân ma trận được tạo từ input và 1 ma trận được chương trình tạo sẵn.

```
=> 0x55555555c890:	mov    eax,DWORD PTR [rbp-0x284]  i  //loop 2
=> 0x55555555c8c0:	cmp    eax,DWORD PTR [rbp-0x280]  // j
    → cmp operands: $eax = 0, DWORD PTR [rbp-0x280] = N/A // cmp j,i
=> 0x55555555c8f0:	jne    0x55555555caa5

=> 0x55555555c927:	movzx  edx,BYTE PTR [rbp-0x295]       edx=1(1)
=> 0x55555555c966:	mov    rax,QWORD PTR [rbp-0x278]    
=> 0x55555555c995:	cmp    rax,0x1                            
    → cmp operands: $rax = -600, 0x1 = 1              cmp q(0x7fffffffda68),1
=> 0x55555555c9b7:	sete   al          // al=0
=> 0x55555555c9de:	movzx  eax,al
=> 0x55555555c9fe:	and    eax,edx         // eax=0
=> 0x55555555ca16:	test   eax,eax      
=> 0x55555555ca35:	setne  al         // al=1
=> 0x55555555ca5f:	mov    BYTE PTR [rbp-0x295],al ///   BYTE PTR [rbp-0x295] =1
=> 0x55555555ca8d:	jmp    0x55555555cc1f
=> 0x55555555cc3b:	add    DWORD PTR [rbp-0x280],0x1               // counter DWORD PTR [rbp-0x280]
=> 0x55555555cc7a:	cmp    DWORD PTR [rbp-0x280],0x3
    → cmp operands: DWORD PTR [rbp-0x280] = N/A, 0x3 = 3
=> 0x55555555ccb2:	jle    0x55555555c6fd


=> 0x55555555c712:	mov    eax,DWORD PTR [rbp-0x280] 
=> 0x55555555c73f:	movsxd rdx,eax                 //rdx=j
=> 0x55555555c769:	mov    eax,DWORD PTR [rbp-0x284]
=> 0x55555555c796:	movsxd rsi,eax            //rsi =i
=> 0x55555555c7c7:	lea    rcx,[rbp-0x278]        // rcx=0
=> 0x55555555c806:	lea    rax,[rbp-0x230]        // rax=4; rbp-0x230=4
=> 0x55555555c83b:	mov    rdi,rax                 //rdi=4
=> 0x55555555c863:	call   0x555555555ca0
=> 0x555555555cac:	endbr64                                                     
=> 0x555555555cc5:	push   rbp
=> 0x555555555ce1:	mov    rbp,rsp
=> 0x555555555d02:	sub    rsp,0x30
=> 0x555555555d1e:	mov    QWORD PTR [rbp-0x18],rdi //4
=> 0x555555555d3a:	mov    QWORD PTR [rbp-0x20],rsi // i
=> 0x555555555d56:	mov    QWORD PTR [rbp-0x28],rdx // j
=> 0x555555555d72:	mov    QWORD PTR [rbp-0x30],rcx //0
=> 0x555555555d8e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555db0:	mov    rax,QWORD PTR [rax]   // rax=4
=> 0x555555555dd1:	cmp    QWORD PTR [rbp-0x20],rax 
    → cmp operands: [rbp-0x20] = N/A, $rax = 4
=> 0x555555555df6:	jb     0x555555555e63
=> 0x555555555e6f:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555e8b:	mov    rax,QWORD PTR [rax+0x8] // rax=4
=> 0x555555555ea7:	cmp    QWORD PTR [rbp-0x28],rax /// cmp counter, 4
    → cmp operands: [rbp-0x28] = N/A, $rax = 4
=> 0x555555555ecc:	jb     0x555555555f39
=> 0x555555555f45:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x555555555f61:	mov    rax,QWORD PTR [rax+0x8]    //rax=4
=> 0x555555555f84:	imul   rax,QWORD PTR [rbp-0x20] 
=> 0x555555555fae:	mov    rdx,rax                    // rdx=4*i
=> 0x555555555fcf:	mov    rax,QWORD PTR [rbp-0x28]
=> 0x555555555ff1:	add    rax,rdx                         // rax=4*i+j
=> 0x555555556012:	mov    QWORD PTR [rbp-0x8],rax   // QWORD PTR [rbp-0x8]=4*i+j= k
=> 0x55555555602e:	mov    rax,QWORD PTR [rbp-0x18]
=> 0x55555555604a:	mov    rdx,QWORD PTR [rax+0x10]  
=> 0x555555556066:	mov    rax,QWORD PTR [rbp-0x8]
=> 0x555555556082:	shl    rax,0x3                     
=> 0x5555555560a4:	add    rax,rdx                  
=> 0x5555555560cb:	mov    rdx,QWORD PTR [rax]       
=> 0x5555555560ec:	mov    rax,QWORD PTR [rbp-0x30] 
=> 0x55555555610e:	mov    QWORD PTR [rax],rdx      
=> 0x555555556136:	mov    eax,0x1
=> 0x555555556157:	leave
=> 0x555555556161:	ret
......
```
Đọc tiếp trong file log.txt, chương trình sau khi nhân ma trận sẽ xử lý duyệt qua trận trận thu được và kiểm tra xem liệu với các giá trị có index hàng bằng index cột thì có bằng 1 hay không, với các giá trị còn lại có bằng 0 hay không. Nói cách khác, chương trình so sánh ma trận thu được sau phép nhân với ma trận đơn vị. Mình rút gọn lại logic của đoạn này như sau:
```

=> 0x55555555c8f0:	jne    0x55555555caa5
ZF=0   {
=> 0x55555555cac1:	movzx  edx,BYTE PTR [rbp-0x295]
=> 0x55555555cb00:	mov    rax,QWORD PTR [rbp-0x278]
=> 0x55555555cb35:	test   rax,rax
=> 0x55555555cb5c:	sete   al
=> 0x55555555cb83:	movzx  eax,al
=> 0x55555555cba3:	and    eax,edx
=> 0x55555555cbbb:	test   eax,eax
=> 0x55555555cbda:	setne  al
=> 0x55555555cc04:	mov    BYTE PTR [rbp-0x295],al  
										}
}

ZF !=0 {
=> 0x55555555c927:	movzx  edx,BYTE PTR [rbp-0x295]       
=> 0x55555555c966:	mov    rax,QWORD PTR [rbp-0x278]    
=> 0x55555555c995:	cmp    rax,0x1                            
    → cmp operands: $rax = -600, 0x1 = 1             
=> 0x55555555c9b7:	sete   al          // al=0
=> 0x55555555c9de:	movzx  eax,al
=> 0x55555555c9fe:	and    eax,edx         // eax=0
=> 0x55555555ca16:	test   eax,eax      
=> 0x55555555ca35:	setne  al         // al=1
=> 0x55555555ca5f:	mov    BYTE PTR [rbp-0x295],al ///   BYTE PTR [rbp-0x295] =1
}
```

Đến lúc này, chúng ta đã nhìn ra vấn đề: Input của chúng ta sẽ được xử lý bỏ ký tự '-', thực hiện biến đổi như trên rồi tải vào ma trận, nhân ma trận với một ma trận cho sẵn rồi so sánh với ma trận đơn vị. Việc cuối cùng mình cần làm là tìm ma trận cho sẵn. Debug lại và dễ dàng tìm được ma trận được chương trình tạo sẵn để nhân:

![](http://note.bksec.vn/pad/uploads/add53729-a2d4-4c6f-8247-b7a1638594c0.png)

Như vậy input phải thỏa mãn là ma trận nghịch đảo của ma trận này. Mình tìm ma trận nghịch đảo, truy ngược về password và nhập lại thì mình tìm được flag.

![](http://note.bksec.vn/pad/uploads/6570648b-d2cb-43b0-9571-8dab40752027.png)

### 3. Script

```
import numpy as np

A = np.array([
    [88, -17, 19, -57],
    [45, -9, 10, -29],
    [-56, 11, -12, 36],
    [-40, 8, -9, 26]
])


A_inv = np.linalg.inv(A)


res_rows = []
for i, row in enumerate(A_inv):
    row_chars = []
    for j, val in enumerate(row):
        ascii_code = int(round(val + i * j + 0x41))
        row_chars.append(chr(ascii_code))
    res_rows.append(''.join(row_chars))
res = '-'.join(res_rows)

print(res)

```
### 4. Another approach

 Sau khi mình đọc writeup chính thức, có vẻ như có hẳn một script để deobfuscating file này, và dùng IDA decompile được luôn :(. Việc này sẽ giúp công việc phân tích dễ hơn rất nhiều lần ( so với ngồi đọc full asm như mình ). Mình sẽ để script bên dưới cho mọi người dùng ( hy vọng mọi người dùng nó thay vì cố đọc hết code asm sinh ra từ script trên kia). Còn lại logic của chương trình về cơ bản vấn giống bên trên mình đã trình bày.

```
from pwn import *
import capstone
import sys
import ctypes

def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])

def disas_single(data):
    disas = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    inst = next(disas.disasm(data, 0))
    return inst, inst.size, inst.mnemonic

def deobufscate(elf, code, text_off, text_end, addr, modified):
    stop = False
    while not stop:
        inst, sz, mneumonic = disas_single(code[addr:])
        if mneumonic == 'ret':
            stop = True
        elif mneumonic == 'call':
            call_dst = addr + ctypes.c_int64(int(inst.op_str, 16)).value
            if call_dst >= text_off and call_dst <= text_end:
                deobufscate(elf, code, text_off, text_end, call_dst, modified)
        elif mneumonic == 'xor':
            if '[rip + ' in inst.op_str:
                rip_rel = int(inst.op_str.split('[rip + ')[1].split(']')[0], 16)
                key = int(inst.op_str.split(',')[1], 16)
                decrypt = b''
                if inst.op_str.startswith('qword ptr '):
                    decrypt = xor(p64(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 8])
                elif inst.op_str.startswith('dword ptr '):
                    decrypt = xor(p32(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 4])
                elif inst.op_str.startswith('word ptr '):
                    decrypt = xor(p16(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 2])
                elif inst.op_str.startswith('byte ptr '):
                    decrypt = xor(p8(key), code[addr + sz + rip_rel: addr + sz + rip_rel + 1])
                assert(len(decrypt) in [1, 2, 4, 8])
                for i, b in enumerate(decrypt):
                    modified[addr + sz + rip_rel + i] = b
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            elif '[rip -' in inst.op_str:
                for i in range(addr, addr + sz):
                    modified[i] = 0x90
                if code[addr - 0x1] == 0x9c:
                    modified[addr - 0x1] = 0x90
                if code[addr + sz] == 0x9d:
                    modified[addr + sz] = 0x90
            code = bytes(modified)
        addr += sz


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'{sys.argv[0]} obfuscated main_offset')
        exit(1)
    elf = ELF(sys.argv[1])
    main = int(sys.argv[2], 16)
    text_off = elf.get_section_by_name('.text').header.sh_offset
    text_end = elf.get_section_by_name('.text').header.sh_offset + elf.get_section_by_name('.text').header.sh_size
    sz = text_off + text_end
    with open(elf.path, 'rb') as f:
        full = f.read()
    data = full[:sz]
    modified = bytearray(data)
    deobufscate(elf, data, text_off, text_end, main, modified)
    with open(f'{elf.path}_deobfuscate', 'wb') as f:
        f.write(bytes(modified) + full[sz:])

```
