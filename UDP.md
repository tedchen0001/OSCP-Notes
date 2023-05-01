Nmap

```shell
sudo nmap -sU -T3 -Pn <target ip> --top-ports 200
sudo nmap -p69 --script=tftp-enum.nse <target ip> -sU
```

tftp

```shell
tftp <target ip> -c put <filename>
tftp <target ip> -c get <filename>
```