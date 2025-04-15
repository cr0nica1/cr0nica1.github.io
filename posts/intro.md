+++
date = '2025-04-16T02:31:48+07:00'
draft = true
title = 'K!nd4SUS CTF 2025'
+++


 Đây là giải CTF đầu tiên của mình với CLB BKSEC, tuy vẫn chưa có nhiều kinh nghiệm nhưng mình cũng học hỏi khá nhiều điều từ 2 challenge mình giải được.


## I. The kindling of the first Flag - reverse engineering
### 1. Analysis
Chall là một file python về một trò chơi tìm path thỏa mãn để chương trình in ra flag.

```
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
import random

FLAG = "JlLScp2qTzfFZ7kIYP6Jm5Mv/2h6p26S0OWgmXYdEMAl1Sjg6hwW95bPsZdtiggvHVVv8zM+x7vRw2qOr3ORbw=="
RED = "\033[0;31m"
PURPLE = "\033[0;35m"
ITALIC = "\033[3m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
END = "\033[0m"

# don't mind the crypto stuff
class Cipher:
    def encrypt(self, plainText, key):
        iv = os.urandom(16) 
        privateKey = hashlib.sha256(key.encode("utf-8")).digest() 
        cipher = AES.new(privateKey, AES.MODE_CBC, iv)
        encryptedBytes = cipher.encrypt(pad(plainText.encode(), AES.block_size))  
        return base64.b64encode(iv + encryptedBytes).decode()

    def decrypt(self, encrypted, key):
        encryptedData = base64.b64decode(encrypted) 
        iv = encryptedData[:16] 
        privateKey = hashlib.sha256(key.encode("utf-8")).digest()  
        cipher = AES.new(privateKey, AES.MODE_CBC, iv) 
        try:
            decryptedBytes = unpad(cipher.decrypt(encryptedData[16:]), AES.block_size)  
        except:
            die(1)
        return decryptedBytes.decode()


places = ["Cemetery of Ash", "Grand Archives", "Profaned Capital", "Farron Keep", "Anor Londo", "High Wall of Lothric", "Undead Settlement", "Firelink Shrine", "Road of Sacrifices", "Irithyll Dungeon", "Catacombs of Carthus", "Lothric Castle", "Cathedral of the Deep","Irithyll of the Boreal Valley","Untended Graves","Kiln of the First Flame"]

routes = [
    [60, "Firelink Shrine", "Kiln of the First Flame", "Undead Settlement", "High Wall of Lothric"],
    [-10, "Lothric Castle", "High Wall of Lothric", "Irithyll of the Boreal Valley", "Untended Graves"],
    [12, "Irithyll Dungeon", "Grand Archives", "Undead Settlement", "Kiln of the First Flame"],
    [-5555, "Road of Sacrifices", "Catacombs of Carthus", "Anor Londo", "Cathedral of the Deep"],
    [555, "Irithyll of the Boreal Valley", "Irithyll Dungeon", "High Wall of Lothric", "Cemetery of Ash"],
    [3, "Firelink Shrine", "Undead Settlement", "Lothric Castle", "Untended Graves"],
    [1015, "High Wall of Lothric", "Road of Sacrifices", "Irithyll Dungeon", "Grand Archives"],
    [35, "Kiln of the First Flame", "High Wall of Lothric", "Cemetery of Ash", "Irithyll of the Boreal Valley"],
    [143, "Cathedral of the Deep", "Farron Keep", "Undead Settlement", "Lothric Castle"],
    [1551, "Irithyll of the Boreal Valley", "Profaned Capital", "High Wall of Lothric", "Farron Keep"],
    [70, "Farron Keep", "Irithyll of the Boreal Valley", "Grand Archives", "Firelink Shrine"],
    [77, "High Wall of Lothric", "Untended Graves", "Grand Archives", "Farron Keep"],
    [718640, "Farron Keep", "Road of Sacrifices", "Profaned Capital", "Anor Londo"],
    [869, "Anor Londo", "Irithyll Dungeon", "Catacombs of Carthus", "Road of Sacrifices"],
    [6969, "Lothric Castle", "High Wall of Lothric", "Kiln of the First Flame", "Cathedral of the Deep"]
]

position = ""
path = []

def checkFlag():
    global path
    aes = Cipher()

    a = "" 
    b = ""
    for p in path:
        if path.index(p) % 2 == 0:
            a += f"{p[0]+p[-1]}"
        else:
            b += f"{p[0]+p[-1]}"

    key = a+b
    attempt = aes.decrypt(FLAG,key)

    if "KSUS" not in attempt:
        die(1)
    else:
        print(f"\nYou hear that sweet female voice again, this time clearer.\n{ITALIC}Well done, Unflagged...{END}, she muses as a torn piece of parchment manifests itself in front of you:")
        print(f"{PURPLE}{attempt}{END}")
        exit()


def printLocationDetails():
    global position
    print(f"\nYou find yourself in a place called {PURPLE}{BOLD}{position.upper()}{END}.")
    print("A number of dangerous paths, crawling with enemies, open in front of you... An infinite sea of possibilities.\nWhere will you go?\n")
    for i,r in enumerate(routes[places.index(position)][1:]):
        print(f"\t{i}. {r}")


def die(way):
    quotes = [
        f"As you make your next step, you waste a second to glance at the bloodied path you are about to leave behind. \nOne second too long, as a blazing sword piercing right through you suddenly reminds you. \n{ITALIC}This spot marks our grave, but you may rest here too, if you would like...{END} a young prince whispers.",
        f"The earth trembles and you feel the sudden urge to look to the greyish sky above you.\n{ITALIC}Ignorant slaves, how quickly you forget{END}, a twisted dragon-man spits as he crushes you under his feet.",
        f"The deadly scythe of a woman grabs you by the waist.\n{ITALIC}Return from whence thou cam'st. For that is thy place of belonging{END}, the Sister commands before taking you to your grave.",
        f"In the thick mist, a nun-like figure reveals herself in front of you.\n{ITALIC}Return Lord of Londor. You have your own subjects to attain to{END}, she whispers as she cuts right through you with her scythe."
    ]
    if way:
        print(f"\n{random.choice(quotes)}")
    else:
        print(f"{ITALIC}What is taking you so long?{END}, Patches croons before kicking you off a cliff again.")

    print(f"\n\t{RED}YOU DIED{END}\n")
    exit()


def proceed(next):
    global position
    if sum([0, 0, 0, 1][routes[places.index(position)][0]:routes[places.index(position)][0]+1]) == 1:
        if next > ((221^216)>>True)*((len("...Rise, if you would...for that is our curse...")^53)>>1):
            die(1)
    elif sum(int(d) for d in str(abs(routes[places.index(position)][0]))) % 3 == 0:   
        if next > (int(bool(len("Why, Patches, why?")))):
            die(1)
    elif str(abs(routes[places.index(position)][0]))[-1] in "05":  
        if next > (True << True):
            die(1)
    elif (sum(int(str(routes[places.index(position)][0])[i]) for i in range(0, len(str(routes[places.index(position)][0])), 2)) - sum(int(str(routes[places.index(position)][0])[i]) for i in range(1, len(str(routes[places.index(position)][0])), 2))) % 11 == 0: 
        if next > (sum(map(int,str(111111)[::2]))):
            die(1)

    path.append(routes[places.index(position)][next])   
    position = routes[places.index(position)][next]
        

def play():
    global position
    global path
    while True:
        if position != "Kiln of the First Flame" and len(path) < 22: 
            printLocationDetails() 
            next = int(input("\nChoose a number >   "))
            if next < 0 or next > 3:
                exit()
            proceed(next+1)
        elif position == "Kiln of the First Flame":   
            checkFlag()
        elif len(path) >= 22:
            die(0)


def main():
    global position
    print(f"\n{ITALIC}You slowly rise as you are awaken by a sweet and ageless voice. \n'Let the Flame guide thee in this search for the flag', she whispers softly into your ear. \nBefore you can ask any questions, she disappears. \n\nYou are now left in utter silence.{END}\n")
    print(f"\t{UNDERLINE}PRESS ENTER TO CONTINUE{END}")
    input()
    position = "Cemetery of Ash"
    path.append(position)  
    play()


if __name__ == "__main__":
    main()
    
```

 Khi đạt điều kiện kết thúc của path ( đến vị trí Kiln of the First Flame hoặc độ dài path lớn hơn 22) thì chương trình sẽ gọi check flag. Ở đây chương trình sinh string bằng 1 thuật toán xử lý từ list path, sau đó đưa kết quả thu được mã hóa bằng hàm băm sha256, rồi lấy nó làm key để giải mã Flag. Hàm băm sha256 là không thể đảo ngược ( hoặc có thể theo một vài pháp sư Trung hoa tuyên bố :v ) do vậy phương án mình nghĩ ra là brute force, do số đường đi vẫn đủ nhỏ chấp nhận được.
 
 ### 2. Analyzing constraints
 
 Các ràng buộc đối với path để path hợp lệ nằm bên trong hàm proceed, được obfuscated để khó nhận ra hơn.

```
if sum([0, 0, 0, 1][routes[places.index(position)][0]:routes[places.index(position)][0]+1]) == 1:
    if next > ((221^216)>>True)*((len("...Rise, if you would...for that is our curse...")^53)>>1):
            die(1)
elif sum(int(d) for d in str(abs(routes[places.index(position)][0]))) % 3 == 0:   
    if next > (int(bool(len("Why, Patches, why?")))):
            die(1)
elif str(abs(routes[places.index(position)][0]))[-1] in "05":  
    if next > (True << True):
            die(1)
elif (sum(int(str(routes[places.index(position)][0])[i]) for i in range(0, len(str(routes[places.index(position)][0])), 2)) - sum(int(str(routes[places.index(position)][0])[i]) for i in range(1, len(str(routes[places.index(position)][0])), 2))) % 11 == 0: 
    if next > (sum(map(int,str(111111)[::2]))):
            die(1)

```

Đi vào phân tích từng ràng buộc một, mình sẽ viết lại các ràng buộc để dễ nhìn hơn. Mình sẽ đặt key = routes[places.index(position)][0].

```
if sum([0, 0, 0, 1][routes[places.index(position)][0]:routes[places.index(position)][0]+1]) == 1:
        if next > ((221^216)>>True)*((len("...Rise, if you would...for that is our curse...")^53)>>1):
            die(1)
```
Ở ràng buộc đầu tiên, nó sẽ tương đương với:
```
if key == 3:
        Max_choice=4
```
Điều đó có nghĩa là người chơi sẽ được chọn bước tiếp theo là [0,1,2,3]. Tương tự với 3 ràng buộc còn lại.
```
elif sum(int(d) for d in str(abs(key))) % 3 == 0:
        Max_choice=1
        
elif str(abs(key))[-1] in "05":
        Max_choice=2
elif:
        even_sum = sum(int(d) for d in str(abs(key))[::2])
        odd_sum = sum(int(d) for d in str(abs(key))[1::2])
        if (even_sum - odd_sum) % 11 == 0:
            Max_choce=3

Max_choice =0
```
### 3. Brute force

```
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
import random
from collections import deque
FLAG = "JlLScp2qTzfFZ7kIYP6Jm5Mv/2h6p26S0OWgmXYdEMAl1Sjg6hwW95bPsZdtiggvHVVv8zM+x7vRw2qOr3ORbw=="
RED = "\033[0;31m"
PURPLE = "\033[0;35m"
ITALIC = "\033[3m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
END = "\033[0m"


class Cipher:
    def encrypt(self, plainText, key):
        iv = os.urandom(16) 
        privateKey = hashlib.sha256(key.encode("utf-8")).digest() 
        cipher = AES.new(privateKey, AES.MODE_CBC, iv)
        encryptedBytes = cipher.encrypt(pad(plainText.encode(), AES.block_size))  
        return base64.b64encode(iv + encryptedBytes).decode()

    def decrypt(self, encrypted, key):
        encryptedData = base64.b64decode(encrypted) 
        iv = encryptedData[:16] 
        privateKey = hashlib.sha256(key.encode("utf-8")).digest()  
        cipher = AES.new(privateKey, AES.MODE_CBC, iv) 
        try:
            decryptedBytes = unpad(cipher.decrypt(encryptedData[16:]), AES.block_size)  
        except:
            return ''
        return decryptedBytes.decode()


places = ["Cemetery of Ash", "Grand Archives", "Profaned Capital", "Farron Keep", "Anor Londo", "High Wall of Lothric", "Undead Settlement", "Firelink Shrine", "Road of Sacrifices", "Irithyll Dungeon", "Catacombs of Carthus", "Lothric Castle", "Cathedral of the Deep","Irithyll of the Boreal Valley","Untended Graves","Kiln of the First Flame"]

routes = [
    [60, "Firelink Shrine", "Kiln of the First Flame", "Undead Settlement", "High Wall of Lothric"],
    [-10, "Lothric Castle", "High Wall of Lothric", "Irithyll of the Boreal Valley", "Untended Graves"],
    [12, "Irithyll Dungeon", "Grand Archives", "Undead Settlement", "Kiln of the First Flame"],
    [-5555, "Road of Sacrifices", "Catacombs of Carthus", "Anor Londo", "Cathedral of the Deep"],
    [555, "Irithyll of the Boreal Valley", "Irithyll Dungeon", "High Wall of Lothric", "Cemetery of Ash"],
    [3, "Firelink Shrine", "Undead Settlement", "Lothric Castle", "Untended Graves"],
    [1015, "High Wall of Lothric", "Road of Sacrifices", "Irithyll Dungeon", "Grand Archives"],
    [35, "Kiln of the First Flame", "High Wall of Lothric", "Cemetery of Ash", "Irithyll of the Boreal Valley"],
    [143, "Cathedral of the Deep", "Farron Keep", "Undead Settlement", "Lothric Castle"],
    [1551, "Irithyll of the Boreal Valley", "Profaned Capital", "High Wall of Lothric", "Farron Keep"],
    [70, "Farron Keep", "Irithyll of the Boreal Valley", "Grand Archives", "Firelink Shrine"],
    [77, "High Wall of Lothric", "Untended Graves", "Grand Archives", "Farron Keep"],
    [718640, "Farron Keep", "Road of Sacrifices", "Profaned Capital", "Anor Londo"],
    [869, "Anor Londo", "Irithyll Dungeon", "Catacombs of Carthus", "Road of Sacrifices"],
    [6969, "Lothric Castle", "High Wall of Lothric", "Kiln of the First Flame", "Cathedral of the Deep"]
]
path=[]
check=True

def checkFlag(path):
    aes = Cipher()

    a = "" 
    b = ""
    for p in path:
        if path.index(p) % 2 == 0:
            a += f"{p[0]+p[-1]}"
        else:
            b += f"{p[0]+p[-1]}"

    key = a + b
    #print(f"Testing path: {' -> '.join(path)}") 
    #print(f"Generated key: {key}") 

    try:
        attempt = aes.decrypt(FLAG, key)
        if attempt and "KSUS" in attempt:
            print(f"\nYou hear that sweet female voice again, this time clearer.\n{ITALIC}Well done, Unflagged...{END}, she muses as a torn piece of parchment manifests itself in front of you:")
            print(f"{PURPLE}{attempt}{END}")
            return True  
    except Exception as e:
        pass
    
    return False  

def die(way):
    quotes = [
        f"As you make your next step, you waste a second to glance at the bloodied path you are about to leave behind. \nOne second too long, as a blazing sword piercing right through you suddenly reminds you. \n{ITALIC}This spot marks our grave, but you may rest here too, if you would like...{END} a young prince whispers.",
        f"The earth trembles and you feel the sudden urge to look to the greyish sky above you.\n{ITALIC}Ignorant slaves, how quickly you forget{END}, a twisted dragon-man spits as he crushes you under his feet.",
        f"The deadly scythe of a woman grabs you by the waist.\n{ITALIC}Return from whence thou cam'st. For that is thy place of belonging{END}, the Sister commands before taking you to your grave.",
        f"In the thick mist, a nun-like figure reveals herself in front of you.\n{ITALIC}Return Lord of Londor. You have your own subjects to attain to{END}, she whispers as she cuts right through you with her scythe."
    ]
    if way:
        print(f"\n{random.choice(quotes)}")
    else:
        print(f"{ITALIC}What is taking you so long?{END}, Patches croons before kicking you off a cliff again.")

    print(f"\n\t{RED}YOU DIED{END}\n")
    global check 
    check=False

def get_max_choice(key):
    
    if key == 3:
        return 4
    elif sum(int(d) for d in str(abs(key))) % 3 == 0:
        return 1
    elif str(abs(key))[-1] in "05":
        return 2
    else:
        even_sum = sum(int(d) for d in str(abs(key))[::2])
        odd_sum = sum(int(d) for d in str(abs(key))[1::2])
        if (even_sum - odd_sum) % 11 == 0:
            return 3
    return 0  


def generate_paths(current, path, paths):
    
  
    if current == "Kiln of the First Flame":
        paths.append(path)
        return

    if len(path) >= 22:
        return

    try:
        idx = places.index(current)
    except ValueError:
        return
    route = routes[idx]
    key = route[0]
    max_choice = get_max_choice(key)

 
    for i in range(max_choice):
        next_place = route[i + 1]
        generate_paths(next_place, path + [next_place], paths)



all_paths = []
generate_paths("Cemetery of Ash", ["Cemetery of Ash"], all_paths)
for path in all_paths:
    if checkFlag(path)==True:
        exit()

```
Mình sẽ sinh tất cả các path hợp lệ dựa vào 4 constraint rồi brute force tìm flag.

![alt text](/images/image.png)

## II Turing-Approved - reverse engineering

### 1. Static Analysis

Giải nén Challenge thì gồm có 4 file là execution.sty, interpreted.tex, Makefile và RAM. Đầu tiên mình kiểm tra file Makefile.
 ```
 .PHONY: run

run:
	echo "" > DUMP
	pdflatex --shell-escape interpreted.tex > /dev/null
	tr -d '\n' < DUMP
	rm interpreted.aux interpreted.log interpreted.output
 ```
 Khá kỳ lạ ở đây là pdflatex lại khởi chạy với option --shell-escape, dùng để thực thi các lệnh shell trong file latex.
Mình sẽ kiểm tra bên trong file latex, tức file interpreted.tex xem nó thực thi cái gì.
```
\documentclass{article}
\usepackage[a0paper,landscape]{geometry}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%																%
%		Hi, enjoy the folly		~ S-Mancl						%
%																%
%																%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


\usepackage{execution}
\begin{document}

\pagenumbering{gobble}

\begin{titlepage}
    \pagestyle{empty}
	\begin{center}
		\scalebox{8}{
		{\LARGE Emulation of a CPU using \LaTeX}
		}
		
		\scalebox{8}{
		{\Large It's funny, isn't it?}
		}
	\end{center}
\end{titlepage}

\setup
\fetchdecodeexecwriteback
\printCPU

\end{document}
```
 Ở đây thì mình nhìn thấy title của file pdf được xuất ra là "Emulation of a CPU using \LaTeX", làm mình suy nghĩ đến ý tưởng có thể các câu lệnh được thực thi ở đây là một chương trình mô phỏng CPU.

Sau khi đặt xong title, chương trình chạy 3 lệnh là ```\setup```, ```\fetchdecodeexecwriteback```, và ```printCPU```. Ở bên dưới không có định nghĩa các lệnh này nên có lẽ nó được định nghĩa trong 1 file khác.  Sau một thời gian research thì mình biết rằng file ```.sty``` là file có thể dùng để định nghĩa lệnh trong latex, vì vậy mình sẽ đọc file ```execution.sty``` xem nó định nghĩa 3 lệnh này như thế nào.
Mình mở file này ra thì thực sự nó rất ... dài, mình không thể đọc toàn bộ nên chỉ search các từ khóa ```\setup```, ```\fetchdecodeexecwriteback```, và ```\printCPU``` xem các lệnh này làm gì,

```\setup``` :
```
\newcommand{\setup}{%
    \newwrite\myoutput
    \immediate\openout\myoutput=\jobname.output
    \lgl{Setting up everything, please be patient}

        \newcounter{lineNumber}
        \newcounter{countLetters}
    \setcounter{countLetters}{0}
        \newcounter{exit}
        \newcounter{start}
    \newcounter{end}
    \newcounter{temp}
    \newcounter{temp1}
    \newcounter{temp2}
    \newcounter{temp3}
    \newcounter{temp4}
    \newcounter{temp_}
    \newcounter{temp_1}
    \newcounter{temp_2}
    \foreach \i in {0,...,15}{
        \newcounter{tempregister_\i}
        \setcounter{tempregister_\i}{0}
    }
    \foreach \i in {0,...,15}{
        \newcounter{tempregister1_\i}
        \setcounter{tempregister1_\i}{0}
    }
        \newcounter{PC}%
        \foreach \j in {0,...,511}{
        \foreach \i in {0,...,15}{
            \newcounter{mem\j_\i}
            \setcounter{mem\j_\i}{0}
        }
    }
        \foreach \i in {0,...,7}{
        \foreach \j in {0,...,15}{
            \newcounter{R\i\j}
            \setcounter{R\i\j}{0}
        }
    }
    \foreach \i in {IR,MAR,MDR,PC}{
        \foreach \j in {0,...,15}{
            \newcounter{\i\j}
            \setcounter{\i\j}{0}
        }
    }
    \foreach \i in {0,...,2}{
        \newcounter{CC\i}
        \setcounter{CC\i}{0}
    }
    
    \setcounter{CC1}{1}
    
    \lr
}

\newcommand{\lr}{%
    \setcounter{temp}{0}
    \setcounter{temp1}{0}
    \CatchFileDef{\ramdata}{RAM}{}
    \lgl{Ready to read memory}
    \foreach \bit in \ramdata {
        \ifnum\value{temp1}>15
            \stepcounter{temp}
            \setcounter{temp1}{0}
        \fi
        \ifnum \bit=1
            \setcounter{mem\arabic{temp}_\arabic{temp1}}{1}
        \fi
        \stepcounter{temp1}
    }
    \lgl{RAM loaded into emulated memory}
}
```

```\fetchdecodeexecwriteback``` :

```
\newcommand{\fetchdecodeexecwriteback}{%
        \setcounter{exit}{0}
    \loop
    \ti{PC}%
        \printCPU%
%
%
    \foreach \i in {0,...,15}{%
        \setcounter{IR\i}{\value{mem\arabic{PC}_\i}}%
    }%
    \immediate\write18{printf "\\a" 1>&2;}
%
    \ifnum \value{IR0}=0{
        \ifnum \value{IR1}=0{
            \ifnum \value{IR2}=0{
                \ifnum \value{IR3}=0{
                    \nxti
                    \lits{BR}
                    \pb
                }\else{
                    \lits{ADD}
                    \pa
                    \nxti
                }\fi
            }\else{
                \ifnum \value{IR3}=0{
                    \lits{LD}
                    \pl
                    \nxti
                }\else{
                    \lits{ST}
                    \ps
                    \nxti
                }\fi
            }\fi
        }\else{
            \ifnum \value{IR2}=0{
                \ifnum \value{IR3}=0{
                    \lits{JSR}
                    \pjts
                }\else{
                    \lits{AND}
                    \pan
                    \nxti
                }\fi
            }\else{
                \ifnum \value{IR3}=0{
                    \lits{LDR}
                    \plr
                    \nxti
                }\else{
                    \lits{STR}
                    \psr
                    \nxti
                }\fi
            }\fi
        }\fi
    }\else{
        \ifnum \value{IR1}=0{
            \ifnum \value{IR2}=0{
                \ifnum \value{IR3}=0{
                    \lits{RTI}
                    \prfi
                }\else{
                    \lits{NOT}
                    \pn
                    \nxti
                }\fi
            }\else{
                \ifnum \value{IR3}=0{
                    \lits{LDI}
                    \pli
                    \nxti
                }\else{
                    \lits{STI}
                    \psit
                    \nxti
                }\fi
            }\fi
        }\else{
            \ifnum \value{IR2}=0{
                \ifnum \value{IR3}=0{
                    \lits{JSSR}
                    \pjtsur
                }\else{
                    \lits{RET}
                    \pr
                    \nxti
                }\fi
            }\else{
                \ifnum \value{IR3}=0{
                    \lits{LEA}
                    \plea
                    \nxti
                }\else{
                    \lits{TRAP}
                    \pt
                }\fi
            }\fi
        }\fi
    }\fi

        
    \ifnum \value{exit}=0
    \repeat

    \lgl{Execution has ended}
    \setcounter{temp}{0}
    \setcounter{temp1}{0}
    \lgl{Ready to dump memory}
    

    \foreach \j in {0,...,511}{
        \foreach \i in {0,...,15}{
            \ifnum \value{mem\j_\i}=1%
                \immediate\write18{echo 1 >> DUMP}
            \else
                \immediate\write18{echo 0 >> DUMP}
            \fi
        }
    }
    \lgl{RAM DUMPED SUCCESSFULLY}
    \immediate\closeout\myoutput
}%
```

`\printCPU` : 
```
\newcommand{\printCPU}{
    \td{R0}
    \prr{R0}{\arabic{temp}}{0x\hexa{temp}}
    \td{R1}
    \prr{R1}{\arabic{temp}}{0x\hexa{temp}}
    \td{R2}
    \prr{R2}{\arabic{temp}}{0x\hexa{temp}}
    \td{R3}
    \prr{R3}{\arabic{temp}}{0x\hexa{temp}}
    \td{R4}
    \prr{R4}{\arabic{temp}}{0x\hexa{temp}}
    \td{R5}
    \prr{R5}{\arabic{temp}}{0x\hexa{temp}}
    \td{R6}
    \prr{R6}{\arabic{temp}}{0x\hexa{temp}}
    \td{R7}
    \prr{R7}{\arabic{temp}}{0x\hexa{temp}}
    \tdu{PC}
    \prr{PC}{\arabic{temp}}{0x\hexa{temp}}
    \tdu{IR}
    \prr{IR}{\arabic{temp}}{0x\hexa{temp}}
    \ifnum \value{CC0}=1%
    \prr{CC}{(N)}{0x4}%
    \else{%
    \ifnum \value{CC1}=1%
    \prr{CC}{(Z)}{0x2}%
    \else%
    \prr{CC}{(P)}{0x1}%
    \fi%
    }%
    \fi%
}
```

Lệnh ```\setup``` tạo ra nhiều bộ đếm khác nhau, sau đó điền một số bộ đếm bằng ```\lr```. Trong mô tả của lệnh này thì nó ghi ``` RAM loaded into emulated memory ```. Load file RAM vào bộ nhớ giả lập ?

Lệnh ```\fetchdecodeexecwriteback``` load các số nhị phân vào các 'IR' từ 'bộ nhớ'. Nếu như giả lập CPU như nó mô tả thì IR liệu có phải 'Instruction Register' ? Tiếp đó lệnh này kiểm tra từng giá trị bit xác định các Opcode ( mình đoán dựa vào các giá trị ADD, LDI, RET,... Cộng với việc nó mô tả nó là CPU giả lập, đây có vẻ như là các câu lệnh trong Kiến trúc tập lệnh (ISA) của CPU được giả lập).

Lệnh ```\printCPU``` in các thông tin của các thanh ghi.

Oke vậy là chúng ta đã phân tích cơ bản về mã nguồn, mình sẽ thử chạy nó xem sao.

### 2. Dynamic Analysis

Dùng lệnh ```make run``` để chạy các lệnh bên trong Makefile.

![](http://note.bksec.vn/pad/uploads/29a1d450-b359-4dfa-93fb-8dc6fef658af.png)

![](http://note.bksec.vn/pad/uploads/d41d9699-73cf-48ec-8d28-6f814ba6d733.png)

Tóm gọn lại output như sau
```
echo "" > DUMP
pdflatex --shell-escape interpreted.tex > /dev/null

LC-2>   Setting up everything, please be patient...

LC-2>   Ready to read memory...

LC-2>   RAM loaded into emulated memory...
[ Các bảng mô tả dữ liệu trong Register ]
LC-2>   Found a TRAP...

LC-2>   Execution has ended...

LC-2>   Ready to dump memory...

LC-2>   RAM DUMPED SUCCESSFULLY...

.-------.-------.-------.
|R0     |3772   |0xEBC  |
.-------.-------.-------.
|R1     |3      |0x3    |
.-------.-------.-------.
|R2     |3769   |0xEB9  |
.-------.-------.-------.
|R3     |0      |0x0    |
.-------.-------.-------.
|R4     |0      |0x0    |
.-------.-------.-------.
|R5     |0      |0x0    |
.-------.-------.-------.
|R6     |0      |0x0    |
.-------.-------.-------.
|R7     |0      |0x0    |
.-------.-------.-------.
|PC     |278    |0x116  |
.-------.-------.-------.
|IR     |61477  |0xF025 |
.-------.-------.-------.
|CC     |(P)    |0x1    |
tr -d '\n' < DUMP
[ Một dãy các giá trị nhị phân mà với dòng 'RAM DUMPED SUCCESSFULLY', có thể đoán là RAM sau khi thực thi]
```

Shell của CPU giả lập ghi là LC-2, Mình quyết định research xem LC-2 là gì để hiểu kiến trúc tập lệnh của nó. Đây là kiến trúc của 1 máy tính giả lập Little Computer 2. Có thể tham khảo reference của nó tại đây: https://www.cs.utexas.edu/~fussell/courses/cs310h/simulator/lc2.pdf

Dựa theo tài liệu này mình viết 1 script để dịch các Opcode dễ đọc hơn.

```
with open("RAM") as f:
    RAM = f.read()
f.close()
RAM = [''.join(RAM.split(","))[16*i:16*(i+1)] for i in range(len(RAM.split(","))//16)][1:]
map = {
    "0001": "ADD  ",
    "0101": "AND  ",
    "0000": "BR   ",
    "0100": "JSR  ",
    "1100": "JSRR ",
    "0010": "LD   ",
    "1010": "LDI  ",
    "0110": "LDR  ",
    "1110": "LEA  ",
    "1001": "NOT  ",
    "1101": "RET  ",
    "1000": "RTI  ",
    "0011": "ST   ",
    "1011": "STI  ",
    "0111": "STR  ",
    "1111": "TRAP "
}

RAM = '\n'.join([map[i[0:4]]+i[4:] for i in RAM])

print(RAM)
```
![](http://note.bksec.vn/pad/uploads/5cae6de9-d45a-4ceb-bb0f-651331a34058.png)

Nhìn thì có vẻ dài nhưng mình thấy đây là một chuỗi các khối lệnh lặp lại.

```
LD R2, ??
LD R1, ??
ADD R0, R1, R2
ST R0, ??
Trap x25
BR ?
.....
```
Phần còn lại có vẻ không có ý nghĩa, vì thế mình tập trung vào các khối lệnh này. Ở đây lệnh ```Trap x25``` sẽ làm chương trình dừng thực thi ở mỗi khối lệnh, do vậy để mô phỏng lại chính xác chương trình làm gì mình sẽ patch sạch các câu lệnh này về nope.

Như vậy ý tưởng sẽ là patch tất cả các câu lệnh ```Trap x25``` bằng nop và bỏ qua các lệnh còn lại, thử interpret các giá trị từ RAM rồi chạy xem. Kết quả thì mình thu được flag. 

![](http://note.bksec.vn/pad/uploads/f15102cb-f4b7-49ce-a609-99340005cc1f.png)
### 3. Script

```
state = {
    "PC": 0,
    "registers": [0,0,0,0,0,0,0,0],
    "RAM" : None
}

def RAMload():
    global state
    with open("RAM") as f:
        state["RAM"] = f.read()
    f.close()
    state["RAM"] = [''.join(state["RAM"].split(","))[16*i:16*(i+1)] for i in range(len(state["RAM"].split(","))//16)][1:]

def simulate():
    global state
    map = {
        "0001": add,
        "0101": nope,
        "0000": jump,
        "0100": nope,
        "1100": nope,
        "0010": load,
        "1010": nope,
        "0110": nope,
        "1110": nope,
        "1001": nope,
        "1101": nope,
        "1000": nope,
        "0011": store,
        "1011": nope,
        "0111": nope,
        "1111": trap
    }
    while state["PC"] != len(state["RAM"]):
        curr_instruction = state["RAM"][state["PC"]]
        map[curr_instruction[:4]](curr_instruction[4:])
    print()

def nope(data):
    pass

def add(data):
    global state
    state["registers"][0] = state["registers"][1] + state["registers"][2]
    print(chr(state["registers"][0]),end='')
    state["PC"] += 1

def jump(data):
    global state
    addr = int(data[3:],2)
    if addr:
        state["PC"] = addr
    else:
        state["PC"] += 1

def load(data):
    global state
    DR = int(data[:3],2)
    addr = int(data[3:],2)
    state["registers"][DR] = int(state["RAM"][addr],2)
    state["PC"] += 1

def store(data):
    global state
    state["PC"] += 1

def trap(data):
    global state
    state["PC"] += 1

def print_state():
    global state
    print("PC: {PC} R0: {R0} R1: {R1} R2: {R2}".format(PC=state["PC"],R0=state["registers"][0],R1=state["registers"][1],R2=state["registers"][2]))

if __name__ == "__main__":
    RAMload() 
    simulate() 
```

