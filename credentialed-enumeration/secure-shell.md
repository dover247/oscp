# Secure Shell

### Cracking ssh id\_rsa keys

```
ssh2john id_rsa > crackme
```

```
john --wordlist=/usr/share/wordlists/rockyou.txt crackme
```

```
john --show crackme
```
