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

appData's Temp folder (%TEMP%)

```cmd
C:\Users\<User Account>\AppData\Local\Temp
```

privileges information

```cmd
whoami /priv
whoami /all
```

check network connections 

```
netstat -ano | findstr LISTEN
```
