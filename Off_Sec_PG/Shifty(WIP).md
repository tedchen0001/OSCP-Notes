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
