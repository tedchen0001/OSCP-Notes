### Username Enumeration

```shell
smtp-user-enum -M RCPT -U /usr/share/wordlists/names.txt -t <target ip> -m 10 -f user@example.com
# -M Method EXPN, VRFY or RCPT
# -m Maximum number of processes
# -f MAIL FROM email address. Used only in "RCPT TO" mode
```

### Sending mail tool

options other than using nc or telnet

```shell
sudo apt install sendemail
```

```shell
sendemail -h
sendemail -f test@testcorp.com -t dev@testcorp.com -u 'please help check my file' -m 'thanks you!' -a /tmp/2003.doc -xu user -xp user1234
```