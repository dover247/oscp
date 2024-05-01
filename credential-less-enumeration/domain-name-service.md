# Domain Name Service

<figure><img src="../.gitbook/assets/image (8) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Footprinting the Service

### **DIG - NS Query**

{% code overflow="wrap" %}
```
dig ns inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - Version Query**

{% code overflow="wrap" %}
```shell-session
dig CH TXT version.bind 10.129.120.85
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (11) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - ANY Query**

{% code overflow="wrap" %}
```shell-session
dig any inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### DIG - AXFR Zone Transfer

{% code overflow="wrap" %}
```
dig axfr inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **DIG - AXFR Zone Transfer - Internal**

{% code overflow="wrap" %}
```
dig axfr internal.inlanefreight.htb @10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14) (1) (1).png" alt=""><figcaption><p>Using subdomain internal from previous zone transfer on inlanefreight.htb</p></figcaption></figure>

### **Subdomain Brute Forcing**

### dnsenum

{% code overflow="wrap" %}
```
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (15) (1) (1).png" alt=""><figcaption></figcaption></figure>

### dnsrecon

```
dnsrecon -r 127.0.0.1 -n 127.0.1.1
```

## Passive Subdomain Enumeration

### virustotal

<figure><img src="../.gitbook/assets/image (25) (1).png" alt=""><figcaption></figcaption></figure>

<div align="center">

<figure><img src="../.gitbook/assets/image (26) (1).png" alt=""><figcaption></figcaption></figure>

</div>

### certificates

#### crt.sh

Another source of information we can use to extract subdomains is SSL/TLS certificates. The main reason is Certificate Transparency (CT).

A project that requires every SSL/TLS certificate issued by a Certificate Authority (CA) to be published in a publicly accessible log

<figure><img src="../.gitbook/assets/image (27) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (28) (1).png" alt=""><figcaption><p>perform a curl request to the target website asking for a JSON output as this is more manageable</p></figcaption></figure>

{% code overflow="wrap" %}
```
curl -s "https://crt.sh/?q=domain.com&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

## Passive Infrastructure Identification

### Wayback Machine

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption><p>you can find old versions that may have interesting comments in the source code or files that should not be there</p></figcaption></figure>

### Waybackurls

{% code overflow="wrap" %}
```
wget https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz
```
{% endcode %}

```
waybackurls -dates https://facebook.com > waybackurls.txt
```

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

## Dangerous Settings

| `allow-query`     | Defines which hosts are allowed to send requests to the DNS server.            |
| ----------------- | ------------------------------------------------------------------------------ |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server.  |
| `allow-transfer`  | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones.                                            |
