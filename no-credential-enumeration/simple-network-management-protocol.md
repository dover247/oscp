# Simple Network Management Protocol

#### Scan SNMP

```
snmpwalk -v 2c -c public $ip 1.3.6.1.2.1.1.5.0
```

#### Brute force SNMP secret string

```
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt $ip
```
