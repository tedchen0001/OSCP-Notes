### Mind map

![Splodge ](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Splodge/Splodge.png)

### Enumeration

```
# Nmap 7.92 scan initiated Sun Mar  6 10:25:13 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.180.108/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.180.108/scans/xml/_full_tcp_nmap.xml 192.168.180.108
Nmap scan report for 192.168.180.108
Host is up, received user-set (0.29s latency).
Scanned at 2022-03-06 10:25:14 EST for 812s
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 43:77:53:46:f8:78:c6:cb:c4:c6:b5:f2:61:2a:64:13 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPwvufh9SVq1esIL7otDp06DD4IT3lXLNsiufWRGWZwSq8BB+29e4wiJnBQfAiQFF/dNt5p27eJzYa+OYewPk7Zit35SAICkvHV3NA/zI4pax4JRd5AHM+zroHUcV6SqwX+rd531CPzaAb8Xaak//bMLeNKq2c1JZQeoaYmfbn+Td7ta84bxvT8espah5VcbAem7pave8aO9tPiUbwyv7XcuRQjvka6rpP5PEtsfjV9lZpUySf+aBqCo+pLsiSwKo5TvfZgPWKdy1t+22AxBN9RRdOjL+sUuebhpeFVIJvSdbUZHzadBHKGP3UrBJiJTt4f6ZAPZ0K8u2DVYayc82j
|   256 a5:b4:45:1f:eb:10:ac:1d:fc:64:de:4b:87:ed:7d:ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLLwdPpjO1Ei905tBE6MjbWXmZ184WFpsIrIoICi912YeOtl1bIhE4MKxi9XmFXsiHUfzF+XGVju5DJn6PedwXc=
|   256 44:7c:68:45:db:3d:45:9b:ec:7c:0d:94:6b:9e:31:f5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEu69xrp39qFb1fQ53wr0mHcTOIZlr2Lvez7PabGgwdS
80/tcp   open  http       syn-ack nginx 1.16.1
|_http-title: 403 Forbidden
| http-git: 
|   192.168.180.108:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     .gitignore matched patterns 'bug' 'key'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: initial commit 
|_    Project type: node.js application (guessed from .gitignore)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.16.1
1337/tcp open  http       syn-ack nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Commando
| http-methods: 
|_  Supported Methods: GET HEAD POST
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.6.0 or later
| fingerprint-strings: 
|   Kerberos: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 27265.28208: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2071
|     RProcessStartupPacket
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2071
|     RProcessStartupPacket
|   ZendJavaBridge: 
|_    EFATAL: unsupported frontend protocol 0.0: server supports 2.0 to 3.0
8080/tcp open  http       syn-ack nginx 1.16.1
|_http-title: Splodge | Home
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.16.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5432-TCP:V=7.92%I=9%D=3/6%Time=6224D51A%P=x86_64-pc-linux-gnu%r(SMB
SF:ProgNeg,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend
SF:\x20protocol\x2065363\.19778:\x20server\x20supports\x202\.0\x20to\x203\
SF:.0\0Fpostmaster\.c\0L2071\0RProcessStartupPacket\0\0")%r(Kerberos,8C,"E
SF:\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\x20protocol\
SF:x2027265\.28208:\x20server\x20supports\x202\.0\x20to\x203\.0\0Fpostmast
SF:er\.c\0L2071\0RProcessStartupPacket\0\0")%r(ZendJavaBridge,48,"EFATAL:\
SF:x20\x20unsupported\x20frontend\x20protocol\x200\.0:\x20server\x20suppor
SF:ts\x202\.0\x20to\x203\.0\n\0");

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  6 10:38:46 2022 -- 1 IP address (1 host up) scanned in 812.20 seconds
```

According to the Nmap scan results, the http service running at 80 port has Git repository files.