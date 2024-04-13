# Domain Name Service

<figure><img src="../.gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Footprinting the Service

### **DIG - NS Query**

{% code overflow="wrap" %}
```
dig ns inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - Version Query**

{% code overflow="wrap" %}
```shell-session
dig CH TXT version.bind 10.129.120.85
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - ANY Query**

{% code overflow="wrap" %}
```shell-session
dig any inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

### DIG - AXFR Zone Transfer

{% code overflow="wrap" %}
```
dig axfr inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - AXFR Zone Transfer - Internal**

{% code overflow="wrap" %}
```
dig axfr internal.inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14) (1).png" alt=""><figcaption><p>Using subdomain internal from previous zone transfer on inlanefreight.htb</p></figcaption></figure>

### **Subdomain Brute Forcing**

{% code overflow="wrap" %}
```
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (15) (1).png" alt=""><figcaption></figcaption></figure>

```
dnsrecon -r 127.0.0.1 -n 127.0.1.1
```



## Dangerous Settings

| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
