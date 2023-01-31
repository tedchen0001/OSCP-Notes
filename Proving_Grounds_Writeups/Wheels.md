#### Enumeration

```shell
$ sudo nmap --min-rate 1000 -p- -Pn 192.168.123.202
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 11:24 CST
Warning: 192.168.123.202 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.123.202
Host is up (0.21s latency).
Not shown: 65367 closed tcp ports (reset), 166 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We found three special pages after web directory scanning.

```shell
feroxbuster -u http://192.168.123.202/ -t 40 -w /usr/share/wordlists/dirb/common.txt -d 2 -k -x php,txt,html
```

![image](PIC/Wheels/Wheels_20230131_233704_001.png)
