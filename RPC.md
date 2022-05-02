### Recon Commands

Nmap tcp

```
sudo nmap -p 5353 --script=rpcinfo <target ip>
```

Nmap udp

```
sudo nmap -p 5353 --script=rpcinfo <target ip> -sU
```

rpcinfo

```
rpcinfo -p <target ip>
```