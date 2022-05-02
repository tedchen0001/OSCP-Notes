### Recon Commands

Nmap tcp

```
nmap -p 5353 --script=rpcinfo <target ip>
```

Nmap udp

```
sudo nmap -p 5353 --script=rpcinfo <target ip> -sU
```

Nmap enumeration

```
sudo nmap -Pn -sUC -p5353 <target ip>
```

rpcinfo

```
rpcinfo -p <target ip>
```