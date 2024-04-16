# Internet Message Access Protocol / Post Office Protocol

## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

### Curl

{% code overflow="wrap" %}
```
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption><p>Verbosity to show CN &#x26; domain &#x26; Versioning</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

## Reading Messages

### **OpenSSL - TLS Encrypted Interaction IMAP**

{% code overflow="wrap" %}
```
openssl s_client -connect 10.129.14.128:imaps
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Authenticating

{% code overflow="wrap" %}
```
1 LOGIN robin robin
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Listing

{% code overflow="wrap" %}
```
1 LIST "" *
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Selecting For Use

{% code overflow="wrap" %}
```
1 SELECT DEV.DEPARTMENT.INT
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Fetching All Messages

{% code overflow="wrap" %}
```
f fetch 1:* BODY[]
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption><p>In This Case Only 1 Message was in the Inbox</p></figcaption></figure>

## Dangerous Settings

| Setting                   | Description                                                                               |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `auth_debug`              | Enables all authentication debug logging.                                                 |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons.                              |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated.                   |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |
