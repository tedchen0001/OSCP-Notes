### Proving Grounds Writeups

- AD:Heist, Hutch, Vault, Resourced
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
- [MariaDB 10.2 < 10.2.37, 10.3 < 10.3.28, 10.4 < 10.4.18, and 10.5 < 10.5.9, CVE-2021-27928](https://www.exploit-db.com/exploits/49765)

#### Notes

- When we are unable to obtain a normal response from a remote service using Telnet, it is worth trying Netcat instead.
- Note the directory traversal status code ```401```. A page exists that just needs to be verified.
- Check to see whether the site is enabled for both ```http``` and ```https``` services.
- If database brute-force attack with Hydra triggers ```max_connect_errors``` error. (mysql> show variables like '%[max_connect_errors](https://dev.mysql.com/doc/refman/5.6/en/server-system-variables.html#sysvar_max_connect_errors)%';)[(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)
- [SQLi(manually)](https://github.com/tedchen0001/OSCP-Notes/blob/master/SQLi(manually).md)
- If the site is encrypted, check the ```DNS name``` in the ```certificate``` through browser.
- linpeas: ```Unknown SUID binary```
- Note that the site's upload folder may be writable.
- Check the active ports and using curl to check the service. [frp](https://github.com/fatedier/frp):frpc for target, frps for attacker.
- Check the unknown SUID binaries execution result.
- If the target server does not install mysql client tool try using mysqldump.
- Note that the root folder is accessible through a vulnerability and can be placed SSH public key.
- [Bypass](https://vk9-sec.com/bypass-30x-redirect-with-burpsuite/) HTTP 30X. 
- If you already have root privileges, note whether you can escape environment, e.g., docker.
- Note the ```opt``` folder.
- Symbolic links(Symlinks) can be abused to cause elevation of privilege.
- Note the ```tasks``` scheduled using ```system timers``` (command:systemctl list-timers, services location:/etc/systemd/system/).
- The ```/etc/sudoers``` file controls who can run what commands as what users on what machines and can also control special things such as whether you need a password for particular commands (https://help.ubuntu.com/community/Sudoers).
- Note that sending test command  between different OS when we using poc exploit.
- Note that when we use the exploit test command between different operating systems such as ```id``` and ```whoami```. (You may have found the right exploit but used the wrong test command.)
- Note the creator information in any files we download from the target, e.g., ```pdf```, ```doc```.
- If it is a windows machine, check the ```Program Files``` and ```Program Files (x86)``` folder to see if additional software is installed.
- Note the interesting executable file. ```ILSpy``` .NET assembly browser and decompiler. (Visual Studio Community version also supports)
- Check the information dumped from the AD environment. For example, using the ```ldapdomaindump``` to get the ```domain_users.json``` file and check all the values.
- Proxychains / Forwarding Ports.
- If the ```Git repository``` exists, use the ```ls -la``` command to check all (hidden) files after downloading.
  ```
  git log
  git show <commit-id>
  ```
- Even if we have got the contents of the website from other services such as ftp, we can still do an enumeration of the website directory to make sure that all contents have been found. Note that the file contents may not be the same either.
- If the generated ```cookie``` does not work, note the system time in the VM.
- You can unzip the executable file and check the files it contains.
- If you want to run a file through a schedule set by another user, be careful to use a directory that the user can also access, not `tmp` folder.
- We can also check the cookies of the website.
- Note that some Windows exploit exe files must be run in cmd mode, not in powershell.
- When using the python exploit script, note that the input parameters are case-sensitive.
- `Bad Request - Invalid Hostname. HTTP Error 400. The request hostname is invalid.` you may need to provide a specific fully qualified domain name (FQDN).
- If essential components are missing when running the exploit file, try compiling it on the target machine. For example, 'GLIBC_2.34' not found.
- Check for any hidden directories or files, such as git.
- When collecting the user list, it is possible to include administrator as well. (AD)
- Note the files in the recycle bin.


#### Commands

Used in `Depreciated`

GraphQL

```graphql
{__schema{types{name,fields{name}}}}
{listUsers}
{getOTP(username:"peter")}
```

Used in `Wheels`

XPATH Injection (XML data)

```
') or 1=1 or ('
')] | //password%00
```