# Simple Network Management Protocol

## Footprinting The Service

### **SNMPwalk**

{% code overflow="wrap" %}
```
snmpwalk -v2c -c public 10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (19) (1).png" alt=""><figcaption><p>SNMP Versions versions 1 &#x26; 2c Do Not Require Authentication</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (20) (1).png" alt=""><figcaption><p><code>Snmpwalk</code> is used to query the OIDs with their information</p></figcaption></figure>

### **OneSixtyOne**

{% code overflow="wrap" %}
```
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (21) (1).png" alt=""><figcaption><p>If we do not know the community string, we can use <code>onesixtyone</code> and <code>SecLists</code> wordlists to identify these community strings</p></figcaption></figure>

### Braa

{% code overflow="wrap" %}
```
braa <community string>@<IP>:.1.3.6.*
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (22) (1).png" alt=""><figcaption><p>certain community strings are bound to specific IP addresses, and named with the hostname of the host. sometimes even symbols are added</p></figcaption></figure>

## Dangerous Settings

| Settings                                         |                                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                                  | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |
