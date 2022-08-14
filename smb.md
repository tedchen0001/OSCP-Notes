### Nmap 

```shell
nmap -p 445 --script vuln <target ip>
nmap --script smb-vuln* <target ip>
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery <target ip>
```

### Smbclient

```shell
smbclient -L //192.168.135.39/ -U brett --option='client min protocol=NT1'
```

```shell
smbclient --no-pass -L //192.168.185.125 -p 445
```

```shell
smbclient --no-pass -N \\\\192.168.185.125\\<folder> -p 445
```

```shell
smbclient -m SMB2 -U WIN10Username -L //Client/
```

### /etc/samba/smb.conf

```shell
client max protocol = NT1 
```

```shell
client min protocol = NT1
```

get permissions

```shell
smbmap -H <target ip>
```

change password (STATUS_PASSWORD_MUST_CHANGE)

```shell
smbpasswd -U <user_name> -r <target ip>
```

recursively list dir

```shell
smbmap -d <domain> -H <target ip> -R <Recursively list dirs> --depth <number>
# smbmap -d test.local -H 10.10.10.10 -R shared --depth 10
```

download file

```shell
smbmap -d <domain> -H <target ip> --download "<PATH>\<file>"
# smbmap -d test.local -H 10.10.10.10 --download "shared\test.txt"
```