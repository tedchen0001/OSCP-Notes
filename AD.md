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
# 1
kerbrute_linux_amd64 --dc <Domain Controller> -d <Active Directory Domain> userenum  ~/Documents/userlist.txt
# 2 valid users
kerbrute userenum -d <domain> --dc <domain controller> ~/Documents/userlist.txt | grep "USERNAME" | cut -f1 -d"@" | cut -f4 -d":" | tr -d "[:blank:]" > /tmp/users.txt
```

### :open_file_folder: PowerView

```powershell
# Groups
Get-NetGroup
```

```powershell
# Computers
Get-NetComputer -fulldata
#select
Get-NetComputer -fulldata | select operatingsystem
```

```powershell
# Users
Get-NetUser
# password last set
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount
```

### :open_file_folder: [CrackMapExec](https://mpgn.gitbook.io/crackmapexec/)

```shell
# brute forcing
crackmapexec <protocol> <target ip> -u <users.txt> -p <passwords.txt>
# check password policy
crackmapexec <protocol> <target ip> --pass-pol
# using existing credentials and users to find more credentials 
crackmapexec <protocol> <target ip> -u /tmp/users.txt -p <password> --continue-on-success
```
