
crack SNMP password

```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -p <target port> <target ip>
```

retrieve a subtree of management values

```
snmpwalk -v1 -c public <target ip> .
# -v 1|2c|3 SNMP version
# -c community string, like a password
# . [OID]
```