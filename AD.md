### :open_file_folder: Learning resources

https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

### :open_file_folder: Personal Flow (WIP)

![AD drawio](https://user-images.githubusercontent.com/8998412/171990757-4b3b5a67-de7c-4f44-91fc-1ae6f25df981.png)

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

[Pwn3d!](https://mpgn.gitbook.io/crackmapexec/news-2022/major-release-for-crackmapexec#ldap-getting-the-pwn3d-flag-lets-go-deeper-with-ldap):domain admin flag

```shell
# brute forcing
sudo crackmapexec <protocol> <target ip> -u <user_list.txt> -p <password_list.txt>
# check password policy
sudo crackmapexec <protocol> <target ip> --pass-pol
# using existing credentials and users to find more credentials 
sudo crackmapexec <protocol> <target ip> -u /tmp/users.txt -p <password> --continue-on-success
# using low privilege user to enumerate more users
sudo crackmapexec <protocol> <target ip> -u <username> -p <password> --users
# using low privilege user to enumerate more groups
sudo crackmapexec <protocol> <target ip> -u <username> -p <password> --groups
# enumerate logged users on multiple servers
sudo crackmapexec <protocol> <target ip(s)> -u <username> -p <password> --loggedon-users
# enumerate shares on multiple servers
sudo crackmapexec <protocol> <target ip(s)> -u <username> -p <password> --shares
# list readable share files
sudo crackmapexec <protocol> <target ip(s)> -u <username> -p <password> -M spider_plus
# bruteforcing the RID
sudo crackmapexec <protocol> <target ip(s)> -u <username> -p <password> --rid-brute
```

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

### :open_file_folder: [dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))

[userAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)

[OID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5?redirectedfrom=MSDN): LDAP Matching Rules

```powershell
# http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
# userAccountControl:<LDAP_MATCHING_RULE OID>:=<flags (sum) value>
# inactive accounts (ACCOUNTDISABLE=2)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
```