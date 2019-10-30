# Forensics

Forensics is an interesting category of CTF problems and requires knowing how data can be hidden creatively in existing file formats.

## Windows Analysis

Querying for information on a Windows box can be annoying. Hopefully the below will help.

### Searching Files and Permissions

```posh
# listing hidden files; -Force shows all files (including hidden)
Get-ChildItem -Force
Get-ChildItem -Hidden

# show all streams for a file
dir /r file.txt
Get-Item file.txt -Stream *

# recursive search for filename
dir /s needle
Get-ChildItem -Path C:\*needle* -Recurse -ErrorAction SilentlyContinue -Force

# recursive search for file contents
findstr /s needle *
Get-ChildItem -Path C:\ -Filter *needle* -Recurse -ErrorAction SilentlyContinue -Force

# find volume label for a drive
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Search\VolumeInfoCache\Z:" | Select-Object -Property VolumeLabel

# search for file by hash
Get-ChildItem -Path C:\ -Recurse -Force | Get-FileHash -Algorithm MD5 | Where-Object hash -eq <TARGET HASH> | Select path
```

### Querying System Information

The below groups of snippets make use of both PowerShell and native system binaries.

#### SID-related Queries

```posh
# SID of all local users
Get-LocalUser | Select-Object SID

# SID of current local user
whoami /user
wmic useraccount where name='%username%' get sid

# SID by local username
wmic useraccount where name='<USERNAME>' get sid

# SID by domain user
wmic useraccount where (name='<USERNAME>' and domain='<DOMAIN>') get sid

# user by SID
wmic useraccount where sid='<SID>' get name
```

#### Process Querying

```posh
# dump data from all running processes
Get-CimInstance Win32_Process | Format-List *

# filter by process name
Get-CimInstante Win32_Process -Filter "name = 'notepad.exe'" | Format-List *

# get binary path for all running processes
Get-Process | Select-Object -ExpandProperty Path

# get more-detailed metadata from a single process
Get-Process -ID <PID> | Select-Object *
(Get-Process -ID <PID>).StartInfo.Environment
```

#### Service and Scheduled Task Querying

```posh
# get formatted list of services
Get-Service | Where Status -eq 'Running' | Out-GridView
Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File -filepath .\running-services.txt

# dump data from all services; second command limits to running services
Get-CimInstance Win32_Service | Format-List *
Get-CimInstance Win32_Service -Filter "state = 'running'" | Format-List *

# scheduled task querying
Get-ScheduledTask | Get-ScheduledTaskInfo
Get-WmiObject Win32_ScheduledJob
```

### Security Event IDs of Note

There are some events in the security event log that are probably worth checking out first. A nice complete reference can he found [here](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/), but some highlights are shown in the table below.

| Source     | ID                | Description                              |
| ---------- | ----------------- | ---------------------------------------- |
| SQL Server | 24301             | Change password succeeded                |
| SQL Server | 24298             | Database login succeeded                 |
| SQL Server | 24303             | Change own password                      |
| SQL Server | 24309             | Copy password                            |
| SQL Server | 24354             | Issued a create external library command |
| Windows    | 528,4624          | Logon success                            |
| Windows    | 529-537,539,4625  | Logon failure variations                 |
| Windows    | 538,551,4647      | Logoff                                   |
| Windows    | 592,4688          | Process creation                         |
| Windows    | 601               | Attempt to install service               |
| Windows    | 602,4698          | Scheduled task created                   |
| Windows    | 610               | New trusted domain                       |
| Windows    | 624,4720,4741     | Account created                          |
| Windows    | 626               | Account enabled                          |
| Windows    | 627               | Change password attempt                  |
| Windows    | 629               | Account disabled                         |
| Windows    | 630,4743          | Account deleted                          |
| Windows    | 642,4738,4742     | Account changed                          |
| Windows    | 645-647           | Computer account created/changed/deleted |
| Windows    | 678-681           | Various Logon alerts                     |
| Windows    | 685               | Account name changed                     |
| Windows    | 686               | Password of user accessed                |
| Windows    | 851,852,4946,4947 | Firewall application/port exceptions     |
| Windows    | 861               | Firewall detected listening application  |
| Windows    | 5025,5034         | Firewall service stopped                 |
| Windows    | 4648              | Logon attempted using explicit creds     |
| Windows    | 4782              | Password hash of an account was accessed |
| Windows    | 5379,5381,5382    | Credentials were read                    |
| Windows    | 5142,5143         | Network share object added/modified      |

### Querying the Logs

There are a few ways to query the event logs. If you have access to the Windows machine under triage, it makes sense to use PowerShell.

#### Using `Get-WinEvent`

`Get-EventLog` is a nice tool for pulling back event information from the local computer, but does not have any functionality for filtering results on remote computers before pulling them pack for local filtering with `Where-Object`.

`Get-WinEvent` allows for filtering of events before pulling them back from other systems. Below are some useful `Get-WinEvent` snippets:
```posh
# limit the number of returned events
Get-WinExent -MaxEvents 1

# query the System log
Get-WinEvent -FilterHashTable @{LogName='System'}

# query multiple levels
Get-WinEvent -FilterHashTable @{LogName='Security';Level=1,2,3}

# query on another computer in the network
Get-WinEvent -Computer SomeOtherComputer

# query around a specific time range; can be useful for correlating suspicious events
Get-WinEvent -FilterHashTable @{LogName='Security';StartTime="10/29/2019 11:45:00 AM";EndTime="10/29/2019 12:00:00 PM"}

# filtering by event ID
Get-WinEvent -FilterHashTable @{LogName='Application';Id=4107}

# filtering via xpath to look at specific usernames
Get-WinEvent -LogName 'Security' -FilterXPath "* [System[(EventId='4264')]] and * [EventData[@Name='TargetUserName'] and (Data='Brian' or Data='Administrator')]]"

# search for data within events
Get-WinEvent -FilterHashTable @{LogName='Security';data='Some Suspicious String'}

# fuzzy searching with Where-Object
Get-WinEvent -FilterHashTable @{LogName='Application';Id=602} | ?{$_.Message -like "*scheduled tasks suspicious content*"}

# filter for interesting service / schtasks events
Get-WinEvent -FilterHashTable @{LogName='Security';Id=601,602,4698} | Export-CSV service-schtasks-events.csv

# filter for interesting account modification events
Get-WinEvent -FilterHashTable @{LogName='Security';Id=624,626,627,629,630,642,645,646,647,685,4720,4738,4741,4743,4742} | Export-CSV account-mod-events.csv

# filter for interesting login / logoff events
Get-WinEvent -FilterHashTable @{LogName='Security';Id=528,529,530,531,532,533,534,535,536,537,538,539,551,678,679,680,681,4624,4625,4647,4648} | Export-CSV login-logoff-events.csv

# filter for interesting firewall events
Get-WinEvent -FilterHashTable @{LogName='Security';Id=851,852,861,4946,4947,5025,5034} | Export-CSV firewall-events.csv

# filter for credential access events
Get-WinEvent -FilterHashTable @{LogName='Security';Id=686,4782,5379,5381,5382} | Export-CSV credential-access-events.csv
```

#### Investigating Suspicious Entries

If you come across a base64-encoded PowerShell payload (think `[Convert]::FromBase64String`), you can decode it with:
```sh
echo -n <BASE64 BLOB> | base64 -d | iconv -f UTF-16LE -t ASCII
```

## Office Documents

### `oletools`

Some challenges may involve extracting information from various Microsoft Office files. A good suite of tools for working with these documents is  [`python-oletools`](https://github.com/decalage2/oletools/wiki). See below for more detailed examples for a few of the tools in this collection.

#### `olevba`

If you see files with the extension `.docm`, there is a good chance there is some kind of embedded VBA macro inside that is worth taking a look at. `olevba` will dump this information out for you. Its usage is straightforward:
```sh
olevba the_file.docm
```
