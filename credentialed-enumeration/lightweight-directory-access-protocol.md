# Lightweight Directory Access Protocol

#### Test for information disclosure

{% code overflow="wrap" %}
```
ldapsearch -v -H 'ldap://$ip' -x -D 'USER@DOMAIN.LOCAL' -w 'PASSWORD' -b 'DC=domain,DC=local'
```
{% endcode %}

#### Bloodhound Hunting

```
bloodhound-python -u username -p password  -d $domain -ns $ip -c all
```

```
neo4j start
```

```
/opt/bloodhound/BloodHound-linux-x64/BloodHound --no-sandbox 2>1 /dev/null &
```
