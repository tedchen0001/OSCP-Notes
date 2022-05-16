### :open_file_folder: Learning resources

https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

### :open_file_folder: Commands

NetBIOS-Domain Name

```
enum4linux <target ip> 
```

Enumerating Users

add target domain /etc/hosts

```
127.0.0.1 localhost
<target domain ip> <Active Directory Domain>
```

```
 kerbrute_linux_amd64 --dc <Active Directory Domain> -d <Active Directory Domain> userenum  ~/Documents/userlist.txt
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
