# Lightweight Directory Access Protocol

#### Test for information disclosure

_Dump All ( Null Authentication )_

```
ldapsearch -v -H 'ldap://$ip' -x -D '' -w '' -b 'DC=domain,DC=local'
```

_Dump All ( Anonymous Authentication )_

```
ldapsearch -v -H 'ldap://$ip' -x -b 'DC=domain,DC=local'
```

_ldapenum_

```
ldapenum -d $domain -u "" -p ""
```

```
ldapenum -d $domain
```
