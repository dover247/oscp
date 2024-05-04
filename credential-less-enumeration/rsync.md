# Rsync

## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
sudo nmap -sV -p 873 127.0.0.1
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Probing for Accessible Shares

{% code overflow="wrap" %}
```
nc -nv 127.0.0.1 873
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Enumerating an Open Share

{% code overflow="wrap" %}
```
rsync -av --list-only rsync://127.0.0.1/dev
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>If Rsync is configured to use SSH to transfer files, we could modify our commands to include the -e ssh flag, or -e "ssh -p2222" if a non-standard port is in use</p></figcaption></figure>

{% code overflow="wrap" %}
```
rsync -av rsync://127.0.0.1/dev
```
{% endcode %}
