# Network File Share

## Footprinting the Service

{% code overflow="wrap" %}
```
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Showing Available Shares

{% code overflow="wrap" %}
```
showmount -e 10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Mounting NFS Shares

{% code overflow="wrap" %}
```
mkdir target-NFS
```
{% endcode %}

{% code overflow="wrap" %}
```
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```
{% endcode %}

{% code overflow="wrap" %}
```
cd target-NFS
```
{% endcode %}

{% code overflow="wrap" %}
```
tree .
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **List Contents with Usernames & Group Names**

```
ls -l mnt/nfs/
```

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **List Contents with UIDs & GUIDs**

```
ls -n mnt/nfs/
```

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Unmounting Share

```
sudo umount ./target-NFS
```

<figure><img src="../.gitbook/assets/image (7) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Dangerous Settings

<table data-full-width="false"><thead><tr><th>Option</th><th>Description</th></tr></thead><tbody><tr><td><code>rw</code></td><td>Read and write permissions.</td></tr><tr><td><code>insecure</code></td><td>Ports above 1024 will be used.</td></tr><tr><td><code>nohide</code></td><td>If another file system was mounted below an exported directory, this directory is exported by its own exports entry.</td></tr><tr><td><code>no_root_squash</code></td><td>All files created by root are kept with the UID/GID 0.</td></tr></tbody></table>

