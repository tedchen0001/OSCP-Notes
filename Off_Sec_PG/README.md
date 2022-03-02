### Proving Grounds Walkthrough

- AD:Heist, Hutch, Vault
- BOF:Malbec
- WordPress:SunsetMidnight
- SQLi:Butch
- LibreOffice:Hepet

#### Exploits

- [WordPress Core < 5.2.3](https://www.exploit-db.com/exploits/47690)

#### Notes

- Use ```netcat``` instead of ```telnet```.
- Note the directory traversal status code ```401```. A page exists that just needs to be verified.
- Check to see whether the site is enabled for both ```http``` and ```https``` services.
- If database brute-force attack with Hydra triggers ```max_connect_errors``` error. (mysql> show variables like '%[max_connect_errors](https://dev.mysql.com/doc/refman/5.6/en/server-system-variables.html#sysvar_max_connect_errors)%';)[(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)
- [SQLi(manually)](https://github.com/tedchen0001/OSCP-Notes/blob/master/SQLi(manually).md)
