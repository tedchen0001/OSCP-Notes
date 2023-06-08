
crack SNMP password

```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -p <target port> <target ip>
```

retrieve a subtree of management values

```
snmpwalk -v1 -c public <target ip> .
# -v 1|2c|3 SNMP version
# -c community string, like a password, e.g. public, private 
# . [OID]
```

SNMP enumerator

```
snmp-check <target ip> -c <community string>
```

SNMP ARBITARY COMMAND EXECUTION AND SHELL

https://rioasmara.com/2021/02/05/snmp-arbitary-command-execution-and-shell/ <br>
https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/

```shell
snmpwalk -v<version> -c <community> <target ip> NET-SNMP-EXTEND-MIB::nsExtendObjects
```