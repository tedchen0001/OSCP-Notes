#### Enumeration

```
# Nmap 7.92 scan initiated Thu Feb  3 21:02:50 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.171.89/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.171.89/scans/xml/_full_tcp_nmap.xml 192.168.171.89
Increasing send delay for 192.168.171.89 from 0 to 5 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.171.89 from 5 to 10 due to 28 out of 69 dropped probes since last increase.
Warning: 192.168.171.89 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.171.89
Host is up, received user-set (0.22s latency).
Scanned at 2022-02-03 21:02:51 EST for 1165s
Not shown: 65379 closed tcp ports (reset), 153 filtered tcp ports (no-response)
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTlNTlvI4qQLNU17b70iKB5xuJlNnZ3zMZeHzfG3H5TcsVNmgImTe4FjEez0e4lKqJvTMsxrPVFHTq6gqfYHwN0KN34x0dv0ngrc+wrrWNoHQrQQqeFuTZy0Tt6BY97082YpFvZfDAvAwJoutkyCxeBb1+C9Y7g6kQYXlNFOuHoq/2m6vki9yVW7Bu3IVeLryw/7pnwzb/tr3K86GEsGc8+87ZIyFrgE1Rca/Y1hD03Uk0s/Kpmi3hCybJwPIoB1WmO2Xz2US8xqzuefsX6UzRazFTQKlTCq5gTTkpNE5fJzS/WmvK7w79aoFJPmVBCXOSXkoe9uoi9a64OnsY0jF8ao7uOUJp84QIUyPRLuPXqlxXwZenqt5RKH6dXyw9tsV2Q3BvZwJwvStFjiQFIi2zIp5jmVcYxwqV4CTt7Ev0ybATE00YAfCoS5i2LJR+fquN9XkS4ay3p9qoZZW7Q4uujWfUUaSO/gYLiOTpbTOl4Smgzc+NvqFrUk1OxPttDSc=
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOX6nl2HC2/Prh0l8uVsnAzinDT2+rhj1VasPM8Df3ntzgb8XzQat7zC/nHm0v7yLWo/CjpI6pD+mrBh3P/wuqk=
|   256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBefJyPm1sjN+QedhTj6S1CPbXQZEFXb58RICJh970R8
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/secret.txt
|_http-generator: WordPress 5.4.2
|_http-title: OSCP Voucher &#8211; Just another WordPress site
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
33060/tcp open  socks5  syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe: 
|     Invalid message"
|     HY000
|   Radmin: 
|     authentication.mechanisms
|     MYSQL41
|     SHA256_MEMORY
|     doc.formats
|     text
|     client.interactive
|     compression
|     algorithm
|     deflate_stream
|     lz4_message
|     zstd_stream
|     node_type
|     mysql
|_    client.pwd_expire_ok
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.92%I=9%D=2/3%Time=61FC8D5B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVersi
SF:onBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2B
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fIn
SF:valid\x20message\"\x05HY000")%r(Hello,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20me
SF:ssage\"\x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08
SF:\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(SSLv23SessionReq
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05
SF:\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInva
SF:lid\x20message\"\x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchRe
SF:q,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x
SF:05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvali
SF:d\x20message\"\x05HY000")%r(DistCCD,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Radmin,15D,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0P\x01\0\0\x02\n\x0f\n\x03tls\x12\x08\x08\x01\x12\x04\x08\
SF:x07@\0\nM\n\x19authentication\.mechanisms\x120\x08\x03\",\n\x11\x08\x01
SF:\x12\r\x08\x08J\t\n\x07MYSQL41\n\x17\x08\x01\x12\x13\x08\x08J\x0f\n\rSH
SF:A256_MEMORY\n\x1d\n\x0bdoc\.formats\x12\x0e\x08\x01\x12\n\x08\x08J\x06\
SF:n\x04text\n\x1e\n\x12client\.interactive\x12\x08\x08\x01\x12\x04\x08\x0
SF:7@\0\nn\n\x0bcompression\x12_\x08\x02\x1a\[\nY\n\talgorithm\x12L\x08\x0
SF:3\"H\n\x18\x08\x01\x12\x14\x08\x08J\x10\n\x0edeflate_stream\n\x15\x08\x
SF:01\x12\x11\x08\x08J\r\n\x0blz4_message\n\x15\x08\x01\x12\x11\x08\x08J\r
SF:\n\x0bzstd_stream\n\x1c\n\tnode_type\x12\x0f\x08\x01\x12\x0b\x08\x08J\x
SF:07\n\x05mysql\n\x20\n\x14client\.pwd_expire_ok\x12\x08\x08\x01\x12\x04\
SF:x08\x07@\0");
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 2.6.39 (91%), Linux 3.10 - 3.12 (91%), Linux 3.4 (91%), Linux 4.4 (91%), Synology DiskStation Manager 5.1 (91%), Linux 2.6.35 (90%), Linux 4.9 (90%), Linux 2.6.32 or 3.10 (90%), Linux 3.5 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/3%OT=22%CT=1%CU=39162%PV=Y%DS=2%DC=T%G=Y%TM=61FC8DD9
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10F%TI=Z%II=I%TS=A)SEQ(SP=10
OS:5%GCD=1%ISR=10F%TI=Z%TS=A)OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11
OS:NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE8
OS:8%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)
OS:T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164
OS:%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 45.842 days (since Mon Dec 20 01:09:36 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23409/tcp)
HOP RTT       ADDRESS
1   230.60 ms 192.168.49.1
2   230.85 ms 192.168.171.89

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  3 21:22:17 2022 -- 1 IP address (1 host up) scanned in 1166.42 seconds

```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h29m25s_001.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h39m56s_002.png)

Downloading the secret.txt.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h41m12s_003.png)

Decoding the file, it's a SSH key file.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h41m26s_004.png)

Finding username or you can guess, We remove the first line and the last one.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h45m29s_005.png)

We get the username.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h47m51s_006.png)

Connecting to the target server.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h53m34s_007.png)

![imae](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h55m34s_008.png)

#### Privilege Escalation

Running ```linpeas.sh``` script to exam.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h57m16s_009.png)

There is a SUID misconfiguration.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/InfosecPrep/InfosecPrep_2022.02.04_10h58m25s_010.png)

