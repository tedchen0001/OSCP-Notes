### Recon 

```shell
nmap -p 445 --script vuln <target ip>
nmap --script smb-vuln* <target ip>
nmap -p 139,445 [--script-args=unsafe=1] --script /usr/share/nmap/scripts/smb-os-discovery <target ip>
crackmapexec smb <target ip>
python enum4linux-ng.py -A <target ip>
```

### smbclient.py

from impacket [smbclient.py](https://github.com/fortra/impacket/blob/master/examples/smbclient.py)

```
python smbclient.py <username>:'<password>'@<target ip>
```

### Smbclient

SMBv1

```shell
smbclient -L '//<target ip>/' -U brett --option='client min protocol=NT1'
```

```shell
smbclient --no-pass -L '//<target ip>' -p 445
```

```shell
smbclient --no-pass -N \\\\<target ip>\\<folder> 
```

```shell
smbclient -U "<username>" '//<target ip>/<folder>'
smbclient -U "<username>" --password="<passowrd>" \\\\<target ip>\\<folder>
```

```shell
smbclient -m SMB2 -U <username> -L //Client/
```

### /etc/samba/smb.conf

protocol negotiation failed

```shell
client max protocol = NT1 
```

```shell
client min protocol = NT1
```

```shell
client min protocol = CORE
client max protocol = SMB3
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
# one file
smbmap -d <domain> -H <target ip> --download "<PATH>\<file>"
# e.g.
smbmap -d test.local -H 10.10.10.10 --download "shared\test.txt"

# all files
smbclient '\\<target ip>\<folder>' -N -c 'prompt OFF;recurse ON; mget *' --user=[DOMAIN/]USERNAME[%PASSWORD]] [-N|--no-pass] [--password=STRING] [--pw-nt-hash]
# e.g.
smbclient '\\10.10.11.123\dev' -N -c 'prompt OFF;recurse ON; mget *' --user=test.com/user1 --password=12345678
```

### SMB Server

[smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)

```shell
python smbserver.py <shareName> <sharePath>
```

