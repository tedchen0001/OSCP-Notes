#### Enumeration

The website on port 8081 is running Sonatype Nexus service version 3.21.0-05. The credential is nexus///nexus.(only guess...refer to the official walkthrough)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.08_22h46m50s_001_.png)

We can use [CVE-2020-10199](https://www.exploit-db.com/exploits/49385). I modify the exploit codes to download the ```nc.exe``` from my pc for executing the reverse shell command. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_12h50m27s_002_.png)

The executable file upload successfully.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_13h12m33s_003_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_13h13m45s_004_.png)

We modify the codes again to execute the reverse shell command.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_13h15m22s_005_.png)

We get the shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_13h16m17s_006_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/Billyboss/Billyboss_2021.12.12_13h16m36s_007_.png)




