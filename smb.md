### Smbclient

```
smbclient -L //192.168.135.39/ -U brett --option='client min protocol=NT1'
```
```
smbclient --no-pass -L //192.168.185.125 -p 12445
```
```
smbclient --no-pass -N \\\\192.168.185.125\\<folder> -p 12445
```
```
smbclient -m SMB2 -U WIN10Username -L //Client/
```

### /etc/samba/smb.conf

```
client max protocol = NT1 
```
```
client min protocol = NT1
```
