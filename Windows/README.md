OS Architecture 

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

```
C:\Users\<User Account>\AppData\Local\Temp
```