### :open_file_folder: Learning resources

https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

### :open_file_folder: Commands

NetBIOS-Domain Name

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

```shell
enum4linux-ng -P <target ip>
# -P Get password policy information via RPC 
```

Enumerating Users

add target domain /etc/hosts, if needed

```shell
127.0.0.1 localhost
<target domain ip> <Active Directory Domain>
```

enumerate domain usernames

```shell
 kerbrute_linux_amd64 --dc <Domain Controller> -d <Active Directory Domain> userenum  ~/Documents/userlist.txt
```

### :open_file_folder: PowerView

```
# Groups
Get-NetGroup
```

```
# Computers
Get-NetComputer -fulldata
#select
Get-NetComputer -fulldata | select operatingsystem
```

```
# Users
Get-NetUser
# password last set
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount
```

### :open_file_folder: CrackMapExec

```
# brute forcing
crackmapexec <protocol> <target ip> -u <users.txt> -p <passwords.txt>
# check password policy
crackmapexec <protocol> <target ip> --pass-pol
```
