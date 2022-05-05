#### Walkthrough

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Peppo/rooted202111010131.png)

#### Enumeration

```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/kali/Documents/AutoRecon/results/192.168.121.60/scans/_full_tcp_nmap.txt" -oX "/home/kali/Documents/AutoRecon/results/192.168.121.60/scans/xml/_full_tcp_nmap.xml" 192.168.121.60
```

[/home/kali/Documents/AutoRecon/results/192.168.121.60/scans/_full_tcp_nmap.txt](file:///home/kali/Documents/AutoRecon/results/192.168.121.60/scans/_full_tcp_nmap.txt):

```
# Nmap 7.91 scan initiated Sat Oct 30 11:18:34 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.121.60/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.121.60/scans/xml/_full_tcp_nmap.xml 192.168.121.60
adjust_timeouts2: packet supposedly had rtt of -81715 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -81715 microseconds.  Ignoring time.
Nmap scan report for 192.168.121.60
Host is up, received user-set (0.21s latency).
Scanned at 2021-10-30 11:18:35 EDT for 360s
Not shown: 65529 filtered ports
Reason: 65529 no-responses
PORT      STATE  SERVICE           REASON         VERSION
22/tcp    open   ssh               syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
|_auth-owners: root
| ssh-hostkey: 
|   2048 75:4c:02:01:fa:1e:9f:cc:e4:7b:52:fe:ba:36:85:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzklV3kD0MUV8hlgkTzmIXus0hs0kpUtsw944TP1RKcoGH+RVDKO3+X9tM0O5o4FWlq63/Rgu/MsM+MHhYJzR9SqhCwFN7FtcAumLaykQRuOTOUMWtRqNybqwTC1noDrh1I6zg/hmzNIOHBH7jVFX4hZ18puzP7kUEwLyzTL6gl8OekAnPGYQFNkLDLo1QuSHoPif+835rjirf6Z+AcVHtz+BCrJa+UvtCuDgQk6+hRvASZ/sZk21jTLqe+pc32a1yYnfySXJrfGevezVVeOzWca4Kbt8HcWz7nNmyS8vcr9U/sDD2ZvW0GEVgxneCDSha5zzAt3blNf8xgwaboetx
|   256 b7:6f:9c:2b:bf:fb:04:62:f4:18:c9:38:f4:3d:6b:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBqNWmLnEEMpbdgBBhkcQQqjHi1mO1wl55JIWh4kpqzQYuZaKGZ63cIOppztFxsAowPqOEhImpkEni9fcTflquQ=
|   256 98:7f:b6:40:ce:bb:b5:57:d5:d1:3c:65:72:74:87:c3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOEgaTq2swxYKGv8XDDrdarrUGFDnxl/3X18UjliCfL6
53/tcp    closed domain            reset ttl 63
113/tcp   open   ident             syn-ack ttl 63 FreeBSD identd
|_auth-owners: nobody
5432/tcp  open   postgresql        syn-ack ttl 62 PostgreSQL DB 9.6.0 or later
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
8080/tcp  open   http              syn-ack ttl 62 WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))
|_http-favicon: Unknown favicon MD5: D316E1622C58825727E7E4E6C954D289
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 4 disallowed entries 
|_/issues/gantt /issues/calendar /activity /search
|_http-server-header: WEBrick/1.4.2 (Ruby/2.6.6/2020-03-31)
|_http-title: Redmine
10000/tcp open   snet-sensor-mgmt? syn-ack ttl 63
|_auth-owners: eleanor
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Hello, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 30 Oct 2021 15:22:52 GMT
|     Connection: close
|     Hello World
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 30 Oct 2021 15:22:40 GMT
|     Connection: close
|     Hello World
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sat, 30 Oct 2021 15:22:41 GMT
|     Connection: close
|_    Hello World
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5432-TCP:V=7.91%I=9%D=10/30%Time=617D6342%P=x86_64-pc-linux-gnu%r(S
SF:MBProgNeg,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20fronte
SF:nd\x20protocol\x2065363\.19778:\x20server\x20supports\x202\.0\x20to\x20
SF:3\.0\0Fpostmaster\.c\0L2071\0RProcessStartupPacket\0\0")%r(Kerberos,8C,
SF:"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\x20protoco
SF:l\x2027265\.28208:\x20server\x20supports\x202\.0\x20to\x203\.0\0Fpostma
SF:ster\.c\0L2071\0RProcessStartupPacket\0\0")%r(ZendJavaBridge,48,"EFATAL
SF::\x20\x20unsupported\x20frontend\x20protocol\x200\.0:\x20server\x20supp
SF:orts\x202\.0\x20to\x203\.0\n\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10000-TCP:V=7.91%I=9%D=10/30%Time=617D6341%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\
SF:nDate:\x20Sat,\x2030\x20Oct\x202021\x2015:22:40\x20GMT\r\nConnection:\x
SF:20close\r\n\r\nHello\x20World\n")%r(HTTPOptions,71,"HTTP/1\.1\x20200\x2
SF:0OK\r\nContent-Type:\x20text/plain\r\nDate:\x20Sat,\x2030\x20Oct\x20202
SF:1\x2015:22:41\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World\n")%
SF:r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusReques
SF:tTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n
SF:\r\n")%r(Hello,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConne
SF:ction:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,2F,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(
SF:TLSSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n")%r(SSLv23SessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(X11P
SF:robe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n
SF:\r\n")%r(FourOhFourRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\
SF:x20text/plain\r\nDate:\x20Sat,\x2030\x20Oct\x202021\x2015:22:52\x20GMT\
SF:r\nConnection:\x20close\r\n\r\nHello\x20World\n")%r(LPDString,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(LDAPS
SF:earchReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close
SF:\r\n\r\n")%r(LDAPBindReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConn
SF:ection:\x20close\r\n\r\n")%r(SIPOptions,2F,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nConnection:\x20close\r\n\r\n");
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.11 - 4.1 (93%), Linux 4.4 (93%), Linux 3.16 (90%), Linux 3.13 (90%), Linux 3.10 - 3.16 (88%), Linux 3.10 - 3.12 (88%), Linux 2.6.32 (88%), Linux 3.2 - 3.8 (88%), Linux 3.8 (88%), WatchGuard Fireware 11.8 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=10/30%OT=22%CT=53%CU=%PV=Y%DS=2%DC=T%G=N%TM=617D63B3%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10E%TI=Z%II=I%TS=8)
SEQ(SP=106%GCD=1%ISR=10E%TI=Z%TS=8)
OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M506NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=N)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.118 days (since Sat Oct 30 08:35:20 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Linux, FreeBSD; CPE: cpe:/o:linux:linux_kernel, cpe:/o:freebsd:freebsd

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   211.41 ms 192.168.49.1
2   211.52 ms 192.168.121.60

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 30 11:24:35 2021 -- 1 IP address (1 host up) scanned in 362.49 seconds

```
