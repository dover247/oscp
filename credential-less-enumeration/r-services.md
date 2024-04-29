# R-Services

## Frequently Abused Commands

<table data-full-width="true"><thead><tr><th width="127">Command</th><th width="156">Service Daemon</th><th width="65">Port</th><th width="107">TCP/UDP</th><th>Description</th></tr></thead><tbody><tr><td><code>rcp</code></td><td><code>rshd</code></td><td>514</td><td>TCP</td><td>Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the <code>cp</code> command on Linux but provides <code>no warning to the user for overwriting existing files on a system</code>.</td></tr><tr><td><code>rsh</code></td><td><code>rshd</code></td><td>514</td><td>TCP</td><td>Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the <code>/etc/hosts.equiv</code> and <code>.rhosts</code> files for validation.</td></tr><tr><td><code>rexec</code></td><td><code>rexecd</code></td><td>512</td><td>TCP</td><td>Enables a user to run shell commands on a remote machine. Requires authentication through the use of a <code>username</code> and <code>password</code> through an unencrypted network socket. Authentication is overridden by the trusted entries in the <code>/etc/hosts.equiv</code> and <code>.rhosts</code> files.</td></tr><tr><td><code>rlogin</code></td><td><code>rlogind</code></td><td>513</td><td>TCP</td><td>Enables a user to log in to a remote host over the network. It works similarly to <code>telnet</code> but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the <code>/etc/hosts.equiv</code> and <code>.rhosts</code> files.</td></tr></tbody></table>

## Trusted Hosts File

### /etc/hosts.equiv

<figure><img src="../.gitbook/assets/image (24) (1).png" alt=""><figcaption><p>The /etc/hosts.equiv file contains a list of trusted hosts and is used to grant access to other systems on the network. When users on one of these hosts attempt to access the system, they are automatically granted access without further authentication.</p></figcaption></figure>

### .rhosts

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>The .rhosts file contains a list of trusted hosts and is used to grant access to other systems on the network. When users on one of these hosts attempt to access the system, they are automatically granted access without further authentication.</p></figcaption></figure>

> <mark style="color:red;">Note: The</mark> <mark style="color:red;"></mark><mark style="color:red;">`hosts.equiv`</mark> <mark style="color:red;"></mark><mark style="color:red;">file is recognized as the global configuration regarding all users on a system, whereas</mark> <mark style="color:red;"></mark><mark style="color:red;">`.rhosts`</mark> <mark style="color:red;"></mark><mark style="color:red;">provides a per-user configuration.</mark>

## Scanning for R-Services

```
sudo nmap -sV -p 512,513,514 10.0.17.2
```

<figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Logging in Using Rlogin

{% code overflow="wrap" %}
```
rlogin 10.0.17.2 -l htb-student
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Listing Authenticated Users Using Rwho

```
rwho
```

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Listing Authenticated Users Using Rusers

{% code overflow="wrap" %}
```
rusers -al 10.0.17.5
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
