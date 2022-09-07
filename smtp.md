### Username Enumeration

```shell
smtp-user-enum -M RCPT -U /usr/share/wordlists/names.txt -t <target ip> -m 10 -f user@example.com
# -M Method EXPN, VRFY or RCPT
# -m Maximum number of processes
# -f MAIL FROM email address. Used only in "RCPT TO" mode
```
