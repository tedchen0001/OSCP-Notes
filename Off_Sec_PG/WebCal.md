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
