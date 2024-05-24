# Password Mutations

## Hashcat

{% code overflow="wrap" %}
```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Existing Hashcat Rules

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>
