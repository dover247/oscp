# Object Scoping

## Return Deleted Objects

_Get a deleted object/user properties that may include legacy password pwd base64_

{% code overflow="wrap" %}
```
Get-ADObject -Filter {displayName -eq "TempAdmin"} -IncludeDeletedObjects -Properties
```
{% endcode %}
