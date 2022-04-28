find subdomains

```
dig axfr @<target ip> test.com
```

```
# hw:hide responses
wfuzz -H 'Host: FUZZ.test.com' -u http://test.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 407
```