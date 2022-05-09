### Proving Grounds Writeups

- AD:Heist, Hutch, Vault
- BOF:Malbec
- WordPress:SunsetMidnight
- SQLi:Butch
- LibreOffice:Hepet, Craft
- SeImpersonatePrivilege:Craft
- container:Sirol

#### Exploits

- [WordPress Core < 5.2.3](https://www.exploit-db.com/exploits/47690)
- [XAMPP 7.4.3 - Local Privilege Escalation](https://www.exploit-db.com/exploits/50337)
- [PHP 8.1.0 RCE](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/backdoor_php_8.1.0-dev.py)
- [Apache HTTP Server 2.4.49 & 2.4.50 RCE](https://www.exploit-db.com/exploits/50383)

#### Notes

- Use ```netcat``` instead of ```telnet```.
- Note the directory traversal status code ```401```. A page exists that just needs to be verified.
- Check to see whether the site is enabled for both ```http``` and ```https``` services.
- If database brute-force attack with Hydra triggers ```max_connect_errors``` error. (mysql> show variables like '%[max_connect_errors](https://dev.mysql.com/doc/refman/5.6/en/server-system-variables.html#sysvar_max_connect_errors)%';)[(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)
- [SQLi(manually)](https://github.com/tedchen0001/OSCP-Notes/blob/master/SQLi(manually).md)
- If the site is encrypted, check the ```DNS name``` in the ```certificate``` through browser.
- linpeas: ```Unknown SUID binary```
- Note that the site's upload folder may be writable.
- Check the active ports and using curl to check the service. [frp](https://github.com/fatedier/frp):frpc for target, frps for attacker.
- Check the unknown SUID binaries execution result.
- If the targer server does not install mysql client tool try using mysqldump.
