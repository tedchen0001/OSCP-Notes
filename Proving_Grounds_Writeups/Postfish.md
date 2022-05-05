#### Enumeration

Nmap

```
# Nmap 7.91 scan initiated Fri Jul 16 12:02:54 2021 as: nmap -Pn -p- -sC -sV -T4 -oN Postfish.nmap 192.168.235.137
Nmap scan report for 192.168.235.137
Host is up (0.25s latency).
Not shown: 65525 closed ports
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
25/tcp    open     smtp     Postfix smtpd
|_smtp-commands: postfish.off, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
|_ssl-date: TLS randomness does not represent time
80/tcp    open     http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp   open     pop3     Dovecot pop3d
|_pop3-capabilities: CAPA PIPELINING RESP-CODES AUTH-RESP-CODE SASL(PLAIN) STLS TOP USER UIDL
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
143/tcp   open     imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: more listed have post-login IMAP4rev1 IDLE Pre-login capabilities OK ENABLE LITERAL+ AUTH=PLAINA0001 LOGIN-REFERRALS SASL-IR STARTTLS ID
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
993/tcp   open     ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: listed more have IMAP4rev1 IDLE post-login capabilities OK ENABLE LITERAL+ Pre-login LOGIN-REFERRALS SASL-IR AUTH=PLAINA0001 ID
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
995/tcp   open     ssl/pop3 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE CAPA SASL(PLAIN) USER UIDL TOP RESP-CODES PIPELINING
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2021-01-26T10:26:37
|_Not valid after:  2031-01-24T10:26:37
44056/tcp filtered unknown
52670/tcp filtered unknown
64529/tcp filtered unknown
Service Info: Host:  postfish.off; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 16 12:24:36 2021 -- 1 IP address (1 host up) scanned in 1302.12 seconds
```

Direct connection via IP address failed. Modify `/etc/hosts` file to set up DNS.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.07.17_01h54m50s_001_.png)

Website has nothing.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.07.24_13h22m39s_001_.png)

Using smtp-user-neum to identify the active user ```hr``` and ```sales``` exist.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.07.30_01h50m55s_001_.png)

Guessing the password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.07.24_14h06m50s_002_.png)

Reading the message through pop service.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postman_2021.08.01_16h00m49s_007_.png)

(I am stuck here. Referring to other walkthroughs below.)

Because the sales department seems to use an unsafe password, check the employees of the sales department first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h17m47s_008_.png)

Using a ![script](https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py) to generate test usernames.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h25m12s_009_.png)

Using smtp-user-neum to identify again, then get a username ```Brian.Moore```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h34m35s_010_.png)

The concept is to send a phishing email for user to click and send a connect-back shell. Setting up a local listener on port 80.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h44m30s_012_.png)

Now send a email with a phishing link to Brain.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h52m08s_013_.png)

After waiting for a while, get the message contains the password entered by Brain.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_16h55m48s_014_.png)

Using that password to connect to SSH, we obtained user rights.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_17h15m15s_016_.png)

#### Privilege Escalation

An interesting file ```/etc/postfix/disclaimer``` appears during the linpeas.sh check.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_17h59m58s_018_.png)

Referring to the website description. This setting will be triggered when sending mail, so we can modify and add the reverse shell command.

(:warning:During the test, it was found that ```/etc/postfix/disclaimer``` would be reset for a period of time.)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_21h05m59s_019_.png)

Setting to listen on port 80.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_21h33m14s_023_.png)

Sending mail to trigger the disclaimer setting.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_21h07m59s_020_.png)

We now get the shell back, and then check through linpeas.sh that mail binary can be executed without a password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_21h10m27s_021_.png)

Referring to [gtfobins](https://gtfobins.github.io/gtfobins/mail/).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_22h18m46s_024_.png)

Gaining the root shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Postfish/Postfish_2021.08.01_21h11m42s_022_.png)
