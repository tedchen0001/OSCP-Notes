#### Enumeration

```shell
$ sudo nmap --min-rate 1000 -p- -Pn 192.168.123.202
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 11:24 CST
Warning: 192.168.123.202 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.123.202
Host is up (0.21s latency).
Not shown: 65367 closed tcp ports (reset), 166 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We found three special pages after web directory scanning.

```shell
feroxbuster -u http://192.168.123.202/ -t 40 -w /usr/share/wordlists/dirb/common.txt -d 2 -k -x php,txt,html
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230131_234350_001.png)

I try to use username `admin` for the SQL injection login test, but it doesn't work.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_225547_002.png)

Next we register an account with username `admin` and then log in to the website. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_225707_003.png)

Switching to the employee portal page and it shows `Access Denied`. So it is not a valid account.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_225808_004.png)

After trying other testing methods (e.g., subdomain, cookie...), I find an e-mail address at bottom of the index page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_225906_005.png)

Using the e-mail to register an account with username tester and suddenly found that we can access the portal page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_230230_006.png)

When we do a search, the web page shows the user names and we notice that the parameters in the URL bar have changed.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230202_230513_007.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_222613_008.png)

The web page shows an `XML` error message when trying to change the parameter value. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_222653_009.png)

After a while of searching, I find that we can use XML injection attacks. You can find many test methods on the [hacktrick](https://book.hacktricks.xyz/pentesting-web/xpath-injection) website.

I use string extraction to test, using two strings `') or 1=1 or ('` and `')] | //password%00` to find username and passowrd.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_224255_010.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_224506_011.png)

Login successfully via SSH using the first account and password combination.

Runnig linpeas to find an unknown SGID binary `/opt/get-list`. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_225511_013.png)

Runnig get-list binary and it will prompt the usernames according to the selection.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_230354_014.png)

I using `xxd` command to dump the binary information. Based on the analysis `(/bin/cat /root/details/%s)` we use the following inputs to obtain information.

```shell
xxd /opt/get-list
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_230445_015.png)

Recovering root password.

```shell
echo 'root:$6$Hk74of.if9klVVcS$EwLAljc7.DOnqZqVOTC0dTa0bRd2ZzyapjBnEN8tgDGrR9ceWViHVtu6gSR.L/WTG398zZCqQiX7DP/1db3MF0:19123:0:99999:7:::' > shadow.txt
echo 'root:x:0:0:root:/root:/bin/bash' > passwd.txt
unshadow passwd.txt shadow.txt > unshadowed.txt
john --wordlist=/home/kali/Documents/rockyou.txt unshadowed.txt
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_231852_016.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_231909_017.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_233544_018.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Wheels/Wheels_20230206_233729_019.png)
