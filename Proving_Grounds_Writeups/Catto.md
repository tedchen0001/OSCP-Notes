#### Walkthrough

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/rooted202110302303.png)

#### Enumeration

Nmap

```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/_full_tcp_nmap.txt" -oX "/home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/xml/_full_tcp_nmap.xml" 192.168.206.139
```

[/home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/_full_tcp_nmap.txt](file:///home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/_full_tcp_nmap.txt):

```
# Nmap 7.91 scan initiated Wed Oct 27 11:46:29 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/scans/xml/_full_tcp_nmap.xml 192.168.206.139
Increasing send delay for 192.168.206.139 from 0 to 5 due to 1297 out of 3241 dropped probes since last increase.
adjust_timeouts2: packet supposedly had rtt of -1835560 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1835560 microseconds.  Ignoring time.
Nmap scan report for 192.168.206.139
Host is up, received user-set (0.21s latency).
Scanned at 2021-10-27 11:46:31 EDT for 1205s
Not shown: 65528 closed ports
Reason: 65528 resets
PORT      STATE SERVICE REASON         VERSION
8080/tcp  open  http    syn-ack ttl 63 nginx 1.14.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.1
|_http-title: Identity by HTML5 UP
18080/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.37 ((centos))
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
30330/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-favicon: Unknown favicon MD5: BC550ED3CF565EB8D826B8A5840A6527
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
35747/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
39529/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, DistCCD, Hello, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, Radmin, SIPOptions, SMBProgNeg, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
42022/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 cc:21:51:f2:c6:2a:ad:d6:ca:07:04:de:70:5f:fa:13 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4sO3kdviVPNeuwbrKWi5q+4eElUHgjIPPgbtcbGXSx1FIM3ptYjJPpGSP1wVEcZL1iKrMx+we3j0u+UX1f1Rg9o0KsUt/XcqgFmEAwEoixwmZ/RIN9zNYQ/GZsmrOgMFz4EqQjB4k7XRKljaKbZoMDvWxfGOPMdyWjYZWGJmXoiykxELLE76ZefH03ZakIKLNhAfDoiAaK8vy1FlG9ubiZFQDmu8oEkeZuXolDWivfO9dEMILdBw0V6+azll+TRVRK35cvsh9J9u8XE9d1ZKu5iPutur2+F2bMXP3xSXP8mVcv+ILpccmxrnMog6LePRil6XS5/07XpW3igtH2BRljCrnIus0GNZ+sHH7yQ/uFy8YB+PEHYFgKqJnV3Ef6x7qLj+yh/YodL509roXup+DNpyB6UW1txnH3oShyK2ueiZ1YKPqzugxGCLOTovDBiGNtKfXxu1zFabLtUsAc+zlqzSLWcfqh/rYw6tHHZSWrx5rGMNeFJ+rx1gTiuuUSEE=
|   256 05:e4:90:d2:00:2b:9d:14:e3:9f:44:68:d2:8e:bc:dc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKs+nIUzvQSjDApNdFM1xkn0nIvh1G2k9p7O2yk0N3I+4VqsHwlbG8a+jM50Ep2WfccT6l1PmM6LxUuwzarQs1w=
|   256 ca:80:49:73:f0:c8:05:ae:bd:2b:42:37:1d:13:e0:71 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLjHYcabXSVangls2dlfJbJlCemLtrImilhDAOOXQYl
50400/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Error
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port39529-TCP:V=7.91%I=9%D=10/27%Time=6179789E%P=x86_64-pc-linux-gnu%r(
SF:RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20cl
SF:ose\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConn
SF:ection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusRequestT
SF:CP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r
SF:\n")%r(Hello,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,2F,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(TL
SF:SSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20cl
SF:ose\r\n\r\n")%r(SSLv23SessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(X11Pro
SF:be,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r
SF:\n")%r(LPDString,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(LDAPSearchReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(LDAPBindReq,2F,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SIPOptions,2F,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(L
SF:ANDesk-RC,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clos
SF:e\r\n\r\n")%r(TerminalServer,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Connection:\x20close\r\n\r\n")%r(NCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nConnection:\x20close\r\n\r\n")%r(NotesRPC,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DistCCD,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(JavaR
SF:MI,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r
SF:\n")%r(Radmin,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n");
OS fingerprint not ideal because: maxTimingRatio (2.640000e+00) is greater than 1.4
Aggressive OS guesses: Linux 4.4 (94%), Linux 4.9 (94%), Linux 3.10 - 3.12 (94%), Linux 4.0 (92%), Linux 3.10 (92%), Linux 3.10 - 3.16 (92%), Linux 3.11 - 4.1 (91%), Linux 2.6.32 (91%), Linux 2.6.32 or 3.10 (91%), Linux 3.4 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=10/27%OT=8080%CT=1%CU=42553%PV=Y%DS=2%DC=T%G=N%TM=6179790C%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=109%TI=Z%TS=A)
OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%T=40%W=7210%O=M506NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=N)
T7(R=N)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 4.475 days (since Sat Oct 23 00:41:59 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   248.88 ms 192.168.49.1
2   248.93 ms 192.168.206.139

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 27 12:06:36 2021 -- 1 IP address (1 host up) scanned in 1207.12 seconds

```

Based on the nmap scanning results, We discover the port 35747 has two APIs: trackEvent and trackError.

/home/kali/Documents/OffSecPG/Catto/AutoRecon/results/192.168.206.139/report/report.md/192.168.206.139/Services/Service - tcp-35747-http/Nmap HTTP.md

```
PORT      STATE SERVICE REASON         VERSION
35747/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-chrono: Request times for /; avg: 585.62ms; min: 536.04ms; max: 649.36ms
|_http-comments-displayer: Couldn't find any comments.
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-date: Wed, 27 Oct 2021 16:07:03 GMT; 0s from local time.
|_http-devframework: Express detected. Found Express in X-Powered-By Header
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
| http-errors: 
| Spidering limited to: maxpagecount=40; withinhost=192.168.206.139
|   Found the following error pages: 
|   
|   Error Code: 404
|   	http://192.168.206.139:35747/trackEvent
|   
|   Error Code: 404
|_  	http://192.168.206.139:35747/trackError
```

I accidentally send the request with wrong json format and then server responses exception error message. In the error message we found the username ```marcus```.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_16h07m03s_001_.png)

I use the username to perform SSH login brute-force attacks. But it didn't find the correct password.

(Refer to the official walkthrough)

We can know that the application being performed on port 30330 is [Gatsby](https://github.com/gatsbyjs/gatsby).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_16h33m59s_002_.png)

In Gatsby development mode it can use ```GraphQL Playground``` to interact with the data by setting. You can refer to the official manual [here](https://www.gatsbyjs.com/docs/using-graphql-playground/#gatsby-skip-here).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_17h10m16s_003_.png)

We connect to the interface ```http://192.168.121.139:30330/__graphql```. The navigation menu has a option ```allSitePage```. We can use it to find the all the nodes in the database includes the hidden pages.

```
query MyQuery {
  allSitePage {
    edges {
      node {
        id
      }
    }
  }
}
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_17h33m13s_004_.png)

We found a hidden sitepage ```/new-server-config-mc```. Navigate to the page ```http://192.168.121.139:30330/new-server-config-mc``` it shows a new password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_17h48m11s_005_.png)

We use previously obtained username and password to log in to server via SSH Connection.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_17h58m01s_006_.png)

(further explain how to get usernames)

Offical walkthrough collects the possible usernames from ```Minecraft - The Island``` page and then uses hydra to guess the correct username. (e.g. hydra -L usernames.txt -p WallAskCharacter305 .....)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_18h03m34s_007_.png)

#### Privilege Escalation

Because this lab is difficult for me, if you want to know the concept behind privilege escalation, please refer to the office walkthrough.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Catto/Catto_2021.10.30_20h02m31s_008_.png)

