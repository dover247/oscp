# Remote Desktop Protocol



## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## RDP Security Check - Installation

{% code overflow="wrap" %}
```
sudo cpan
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **RDP Security Check**

{% code overflow="wrap" %}
```
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
```
{% endcode %}

```
./rdp-sec-check.pl 10.129.201.248
```

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>A Perl script named rdp-sec-check.pl has also been developed by Cisco CX Security Labs that can unauthentically identify the security settings of RDP servers based on the handshakes.</p></figcaption></figure>

## Initiate an RDP Session

{% code overflow="wrap" %}
```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
