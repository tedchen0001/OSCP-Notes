### Recon 

```shell
nmap -p 445 --script vuln <target ip>
nmap --script smb-vuln* <target ip>
nmap -p 139,445 [--script-args=unsafe=1] --script /usr/share/nmap/scripts/smb-os-discovery <target ip>
crackmapexec smb <target ip>
python enum4linux-ng.py -A <target ip>
```

### Smbclient

```shell
smbclient -L //192.168.135.39/ -U brett --option='client min protocol=NT1'
```

```shell
smbclient --no-pass -L //192.168.185.125 -p 445
```

```shell
smbclient --no-pass -N \\\\192.168.185.125\\<folder> 
```

```shell
smbclient -U "<username>" //<target ip>/<folder>
smbclient -U "<username>" --password="<passowrd>" \\\\<target ip>\\<folder>
```

```shell
smbclient -m SMB2 -U <username> -L //Client/
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
smbpasswd -U <username> -r <target ip>
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

### SMB Server

[smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)

```shell
python smbserver.py <shareName> <sharePath>
```