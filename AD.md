#### NetBIOS-Domain Name

```
enum4linux <target ip> 
```

#### Enumerating Users

add target domain /etc/hosts

```
127.0.0.1 localhost
<target domain ip> <Active Directory Domain>
```

```
 kerbrute_linux_amd64 --dc <Active Directory Domain> -d <Active Directory Domain> userenum  ~/Documents/userlist.txt
```