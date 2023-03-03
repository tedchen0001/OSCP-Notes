#### Enumeration

Performing network service reconnaissance using Nmap.

```shell
└─$ sudo nmap --min-rate 1000 -p- -Pn 192.168.175.227 -sC -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 10:21 CST
Nmap scan report for 192.168.175.227
Host is up (0.29s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62361a5cd3e37be170f8a3b31c4c2438 (RSA)
|   256 ee25fc236605c0c1ec47c6bb00c74f53 (ECDSA)
|_  256 835c51ac32e53a217cf6c2cd936858d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: TsukorERP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Trying to log in using common credentials and SQL injection, but unable to gain access.