# Secure Shell

## Footprinting The Service

### **SSH-Audit**

{% code overflow="wrap" %}
```
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
```
{% endcode %}

```
./ssh-audit.py 10.129.14.132
```

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption><p>ssh-audit checks the client-side and server-side configuration &#x26; general information and which encryption algorithms are still used by the client and server. This could be exploited by attacking the server or client at the cryptic level later</p></figcaption></figure>

### Bruteforce with hydra

_Use any found usernames and use "-e nsr" for a less complicated brute force attack then with a wordlist_

```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/probable-v2-top12000.txt
/usr/share/seclists/Passwords/probable-v2-top1575.txt
/usr/share/seclists/Passwords/probable-v2-top207.txt
```

## Dangerous Settings

| Setting                      | Description                                 |
| ---------------------------- | ------------------------------------------- |
| `PasswordAuthentication yes` | Allows password-based authentication.       |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.          |
| `PermitRootLogin yes`        | Allows to log in as the root user.          |
| `Protocol 1`                 | Uses an outdated version of encryption.     |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.             |
| `PermitTunnel`               | Allows tunneling.                           |
| `DebianBanner yes`           | Displays a specific banner when logging in. |
