# Intelligent Platform Management Interface

## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Default Credentials

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |

## **Metasploit Dumping Hashes**

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>We can turn to a flaw in the RAKP protocol in IPMI 2.0 with Metasploit's <em>IPMI 2.0 RAKP Remote SHA1 Password Hash</em> Retrieval module</p></figcaption></figure>

