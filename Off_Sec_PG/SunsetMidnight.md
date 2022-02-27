#### Enumeration

Browsing to port 80 HTTP service through IP address fails and it returns a domain name ```sunset-midnight```. We need to modify DNS settings first.

![image](1)

We add a DNS rule in ```/etc/hosts``` file.

![image](2)
 
Browsing to port 80 HTTP service again, and this time we see a webpage built with WordPress.

![image](3)

The WordPress plugin we find is ```Simply Poll``` but its real version is 1.5, not 1.4.1 which has a vulnerability.

![image](4)

After a lot of searching, I can't find the breakthrough of the WordPress website. So I move to port 3306 and try to brute-force database password.

I try to use the account ```wordpress``` but fail. [(*understanding max_connect_errors*)](https://www.virtual-dba.com/blog/mysql-max-connect-errors/)

```
hydra -l wordpress -P ~/Documents/rockyou.txt -s 3306 -t 4 -f 192.168.128.88 mysql
```

![image](5)

Change the account to root to try and we successfully get the password.

Browsing to WordPress database we find the password for admin.

We change the password to ```admin123```.

Logging in to WordPress dashboard. We can [upload and activate a malicious plugin](https://book.hacktricks.xyz/pentesting/pentesting-web/wordpress#uploading-and-activating-malicious-plugin).
