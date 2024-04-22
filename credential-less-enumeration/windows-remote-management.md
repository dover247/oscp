# Windows Remote Management

## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

## WRM Interaction

{% code overflow="wrap" %}
```
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>
