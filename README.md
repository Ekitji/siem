# Offensive SIEM
Practical techniques for leveraging SIEM as an offensive discovery tool, helping defenders think like attackers to strengthen security from within.

## Queries
See above - queries.md file.

Will keep getting updated when needed. The idea is to have layer on layer coverage using different event.codes/event.providers.
* Released queries for environmental PATHS, Kernel Drivers and Logon/Startup scripts etc during february 2026!
* Released queries for OpenSSL libraries and Schedule task / Services with missing binary paths during mars 2026!

### Vulnerability Management
Queries for Vulnerability Management in file: vulnerabilitymanagement.md
#### Gives you an idea how you can enumerate
- Windows OS version and build status
- Attack Surface Reduction (ASR) Rules and find misconfigurations 
- Windows Defender exclusions and find misconfigurations
- Windows Applocker rules and find misconfigurations
  
## Ping us if/when you find something 
We hope that you liked the presentation. Ping us if you (i would say when you) find vulnerabilities by using this method. A simple message like "one of your queries cathed good stuff".. is more then enough :) do it by commiting to the ping.md file or contact us in alternative ways! We would be happy to share your success!

## General information
The repo will assist you in having offensive mindset. 
Repo is to share the material and queries that we talked about in our presentation:

#### Offensive SIEM - When The Blue Team Switches Perspective
⭐ https://www.youtube.com/watch?v=5nfL_4ek4dY

We have included the most interesting ACL related parts and have tips & tricks.

Check out the outstanding webinars about windows local privilege escalation and windows endpoint misconfigurations which will assist you further on. There are more areas to look into.. This is only the starting point. If you build good queries in other areas - please share it with us so more in the community can use them.

The queries with ⭐ mark is extra highly relevant.
The topics down below with ⭐ is really good content.


### Webinars
#### Oddvar Moes Windows Client Privilege Escalation ⭐
a must to watch, specially the ACL for binaries, services and schedule tasks. 
- https://www.youtube.com/watch?v=EG2Mbw2DVnU
#### Spencers Windows Endpoint Misconfigs ⭐
Topic 2 (Insecurely installed/conf Software) And Topic 5 (Insecure Services And Tasks)
- https://go.spenceralessi.com/windowsmisconfigsreplay
##### password: P3yGQ+1y
- https://www.youtube.com/watch?v=JWopwNVP_to


### Other related to Windows Privilege Escalation.
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html  
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
#### DLL Hijacking
- https://itm4n.github.io/windows-dll-hijacking-clarified/
#### PATH entries and User-writable directories in the system PATH --> DLL Hijacking
- https://www.expressvpn.com/blog/cybersecurity-lessons-a-path-vulnerability-in-windows/
- https://www.praetorian.com/blog/red-team-local-privilege-escalation-writable-system-path-privilege-escalation-part-1/
#### SCCM / Software Center ⭐
- https://blog.nviso.eu/2022/05/31/cve-farming-through-software-center-a-group-effort-to-flush-out-zero-day-privilege-escalations/
##### Interesting read about how many misconfigured software where found and you will likely find same ratio using Offensive SIEM!
#### Arbitrary File deletion --> Local privilege escalation
- https://cicada-8.medium.com/were-going-the-wrong-way-how-to-abuse-symlinks-and-get-lpe-in-windows-0c598b99125b
- https://cloud.google.com/blog/topics/threat-intelligence/arbitrary-file-deletion-vulnerabilities/
- https://github.com/ZeroMemoryEx/CVE-2025-68921
- https://xmcyber.com/blog/jumpshot-xm-cyber-uncovers-critical-local-privilege-escalation-cve-2025-34352-in-jumpcloud-agent/
- https://www.youtube.com/watch?v=EG2Mbw2DVnU  from minute: 34.45 (Intel Trusted Connect Service client)
- https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks
- https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/
##### Other file operations
- https://troopers.de/downloads/troopers19/TROOPERS19_AD_Abusing_privileged_file_operations.pdf
#### Logon scripts
- https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/
- https://cyberthreatperspective.buzzsprout.com/1731753/episodes/13343207-episode-54-misconfigured-and-dangerous-logon-scripts
- https://offsec.blog/wp-content/uploads/2024/06/How-to-Harden-Active-Directory-to-Prevent-Cyber-Attacks.pdf


#### Kernel drivers and privilege escalation
- https://www.youtube.com/watch?v=U36hAneQeZM

#### OpenSSLs openssl.cnf and privilege escalation
- https://labs.infoguard.ch/advisories/cve-2025-13176_eset-inspect_edr_local-privilege-escalation/
- https://blog.mirch.io/2019/06/10/cve-2019-12572-pia-windows-privilege-escalation-malicious-openssl-engine/
- https://blog.pentryx.ch/local-privilege-escalation-in-lenovo-udc-19dc86d72142?gi=0fe882ea2355
- https://www.triskelelabs.com/blog/cve-2025-2272-forcepoint-endpoint-dlp-privilege-escalation
- https://hackerone.com/reports/622170

#### NSIS installer/uninstaller vulnerability
- https://blog.amberwolf.com/blog/2026/april/next-next-system/

#### DotLocal Redirection vulnerability
- https://web.archive.org/web/20230721193548/https://research.nccgroup.com/2023/07/03/technical-advisory-nullsoft-scriptable-installer-system-nsis-insecure-temporary-directory-usage/
- https://blog.amberwolf.com/blog/2026/april/next-next-system/
- https://youtu.be/Ik1xpsQEVwI?si=P7G1kmnSKdFldCAG
- https://heegong.github.io/posts/Advaned-Installer-Local-Privilege-Escalation-Vulnerability/
- https://www.synaptics.com/sites/default/files/nr-154525-tc-synaptics_displaylink_windows_driver_security_brief_-_oct2023.pdf
- https://github.com/wixtoolset/issues/security/advisories/GHSA-7wh2-wxc7-9ph5
### Example of interesting areas to look into that we have not covered in presentation but we have queries for some of them.
* weak passwords in command_line - that are not following best practices / policies
* weak passwords or sensitive information in powershell admin scripts scriptblock event code: 4104. Search for strings: "SecureString","PSCredential","Password", "passwd"......
* weak passwords in registry  - that are not following best practices / policies
* file creations/deletions of typical files holding sensitive information like passwords.txt, passwords.xslx, unattend.xml etc.
* AlwaysInstallElevated in Registry, Autologons (look if passwords is set)
* Windows Privileges - Look at 4672 (logon with special privileges) And 4704/4705 (assignment/removal of rights)
* Event code 5136 and 5137, AD objects.. look in to the fields: description, info and adminComment, if they have any plaintext passwords.
* Using process creation events and look for sc.exe setting services security descriptor using sdset or sysmons registry event code 13 and checking the ACL value (in binary format of SDDL) and converting it to readable ACL looking for weak ACL permissions set on the service it self.
* Do not assume that Program Files and similar admin-protected directories always have correct ACLs (Access Control Lists). It does happen that applications set incorrect default permissions and are far too permissive. CWE-732, CWE-284, CWE-276
* SeImpersonatePrivilege token on "Network Service or Local Service" accounts running processes in user writable paths --> Potato like attack to get SYSTEM
* etc..

### Other types of vulnerabilities
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
* AD attributes (example event.code:"5136" and Attribute:"msDS-KeyCredentialLink") that are commonly abused. Find misconfigurations and harden AD.
* Linux
etc.. etc..

## Other links ⭐
- https://www.securit360.com/blog/securing-windows-common-misconfigurations-that-give-attackers-the-advantage/
- https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/
- https://www.youtube.com/watch?v=EG78PbCMWpY
- https://cloud.google.com/blog/topics/threat-intelligence/privileges-third-party-windows-installers/


### Software installed in C-root drive. ⭐
Make a process creation query using event.code 1 from SYSMON OR event.code 4688 (or the event.codes for services, schedule tasks, DLL load from C-root subfolders)
Look for applications that are installed in C:\ root drive

##### example: 
          C:\myapplication\myapplication.exe
          C:\myapp\subfolder\myapp.exe
          C:\SoftwareCompany\software.exe
          C:\myapplication\myapplication.dll
          C:\myapp\subfolder\myapp.dll
          C:\SoftwareCompany\software.dll
               

The issue with applications that are installed in C-root folder is that it has per default incorrect ACL permissions which allows Authenticated Users to modify (M) the folder and possibly its files. If the Software installation does not correct the ACL in the installation process will likely result in a privilege escalation (confirm it) if a service or another high privileged process is spawning (ex. myapplication.exe OR myapp.exe) from one of the installation paths in C-roots subfolder.
#### Missed the chance of a Microsoft CVE - someone found it before: https://neodyme.io/en/advisories/cve-2025-47962/

### Services - use offensive mindset ⭐
Gives you an idea of which event codes to use what you will see in the event code it self.
- https://detect.fyi/threat-hunting-suspicious-windows-service-names-2f0dceea204c

##### Registry Hive
- HKLM\SYSTEM\CurrentControlSet\Services\<Service>\Security

Service security descriptors are not stored as plain SDDL in the registry.
The registry only shows a Security subkey in binary format when:
* A descriptor was explicitly written using sc.exe
* Or the service installer created one

Otherwise:
The descriptor is computed from built-in defaults hardcoded in Windows.

Inside that key, you’ll find a value named Security showing Binary format of the SDDL for the service where you can look for to find misconfigured ACL for the service it self. Log them with a well configured Sysmon.



### Schedule task - use offensive mindset ⭐
#### Look for tasks running as SYSTEM, Administrator user or "Domain admin" accounts or other high privileged accounts.
Gives you and idea of which event codes to use and what you will see in the event code it self.
- https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks
##### Interesting fields/keys:
UserId where S-1-5-18 is for the SYSTEM user.

GroupId where S-1-5-32-544 is for local Administrators group.

RunLevel where HighestAvailable will run the task as highest possible privilege for specified user. LeastPrivilege will run the task as lower set privilege (Medium integrity) but if the user is Administrator, a UAC bypass shall help you escalate privileges.

Check winlog.event_data.TaskContent in event.code 4698 for more context which contains almost most of the XML definition of the scheduled task, and it gives you the context of

- Which account it runs as
- Privilege level
- Logon method
- Trigger
- Executed command
- Potential Triggers

`What Microsoft should do is to add the <SecurityDescriptor> element to the event code 4698. When exporting a scheduled task manually gives you the SecurityDescriptor value in the exported XML but not allways in the event code itself.` 

**“The SecurityDescriptor is included in the event, but it is only parsed and visible in events 4700 and 4701 (Task Enabled/Disabled), and is rarely present in 4698 (Task Created).”**


##### Registry Hive
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskPath>\<TaskName>

Inside that key, you’ll find a value named SD showing Binary format of the SDDL for the Scheduled task where you can look for to find misconfigured ACL for the task it self. Log them with a well configured Sysmon.



### Kernel drivers and privilege escalation
#### Look for processes creating .sys files in User-Writable paths using sysmons event code 11 or look for loaded drivers from User-Writable paths using Sysmons event.code 6 (Driver loaded)
Here is a excellent talk describing .sys files and privilege escalation using Bring Your Own Vulnerable Driver (BYOVD) techniques.
- https://www.youtube.com/watch?v=U36hAneQeZM

Summary of the talk showcases snowagent.exe dropping sys-files to `C:\Windows\Temp\cpuz143\cpuz143_x64.sys` and local privilege escalation by using the vulnerable driver for CVE-2021-21551.

### OpenSSL and its openssl.cnf for privilege escalation ⭐
#### What is openssl.cnf?
The OpenSSL DLL (legacy) When compiled if not the --openssldir parameter is specified it defaults to /usr/local/ssl which is in Windows translated to c:/usr/local/ssl, which is a common path where the cnf will be looked for. It sets defaults for certificates/keys and can also load/configure crypto engines or providers.
On Windows, it can reference an engine/provider DLL so OpenSSL can use extra cryptographic modules. This is what we can missuse and point it to a "malicious" dll.
When a application initializes OpenSSL — it has to explicitly call OPENSSL_config(NULL) or CONF_modules_load_file(...) to process the config file. If it does not, 
your engine DLL (malicious one) from openssl.cnf will not be loaded. 

Other common paths where applications may look for openssl.cnf is c:\etc\ssl\ or other custom user-writable paths.

#### The Risk and how to find them
`openssl.cnf` can instruct OpenSSL to load a custom DLL as a crypto engine:

```
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
dynamic = dynamic_section

[dynamic_section]
SO_PATH = C:\\path\\to\\evil.dll
LOAD = EMPTY
init = 0
```

**A practical mental model is:**

process loads libeay32.dll

→ process calls OPENSSL_config(NULL)

→ OpenSSL reads openssl.cnf

→ engine section causes loading of a specified dll load attempt

→ Windows loader accepts dll and its dependencies

***If any step is missing, your DLL will not load.***

A minimal rule you can use while debugging:

If the process only loads libeay32.dll, that is not enough.
It must also call OpenSSL config loading and not disable it.

- Its should call OPENSSL_config to work or
- CONF_modules_load_file or
- OPENSSL_no_config is not set.


No signature check. No verification. Any DLL specified gets loaded, If the process calls OPENSSL_config.
We can query for typical DLL names related to OpenSSL to enumerate possible applications to test more with. We want to check the DLLs OPENSSLDIR and if the process is calling the OpenSSL_conf.
We can check OpenSSLDIR by checking file hash against the list in this repo, or get a copy of the crypto related dll and just run the openssldir_check on the cryptodll (libeay32.dll etc).
We can also use ProcMon to check if the process calls any openssl.cnf. If we see openssl.cnf i procmon then we know for sure that the applications calls for it. In other methods what we want to get is version information (in fields of event.code 7) and which path it loads the openssl.cnf file from by checking file hash against the list in this repo, get a copy of same DLL and do manual check. 


**Example when running openssldir_check.exe**

`openssldir_check32.exe libeay32.dll`

`openssldir_check v1.0 by 0xm1rch`

**Output:**

`SSLeay_version() returned OpenSSL 1.0.1g 7 Apr 2014`

`SSLeay_version() returned OPENSSLDIR: "/usr/local/ssl"`

- ref https://github.com/mirchr/openssldir_check
> Similar output with custom modified openssldir_check which is pre-compiled in this repo.

> Output gives OpenSSL version 1.0.1g and that the OpenSSLDIR is set to **/usr/local/ssl** which is **highly interesting!**

> **Sysmon event.code 7** gives you loaded OpenSSL DLLs and also the version information for the dll in the file.pe.file_version field.


#### Escalation Scenario
1. A service runs as **SYSTEM** and uses OpenSSL
2. OpenSSL DLL calls openssl_conf and reads `C:\usr\local\ssl\openssl.cnf` on startup but that file is editable or missing
3. If a low privileged user can write to that folder they can:
   - Drop a malicious `openssl.cnf`
   - Drop their DLL
   - Wait for service restart
   - Code executes as **SYSTEM**

> Result: Local privilege escalation by planting a openssl.cnf which the applications openssl dll loads and ends with loading a custom "malicious" dll.



### NSIS installer/uninstaller vulnerability

NSIS is a widely used Windows installer framework. The issue described here is that, when an NSIS installer or uninstaller runs with elevated privileges, it may use temporary directories under C:\Windows\Temp in a way that a normal local user can interfere with.

In practice, that means a low-privileged attacker can take control of files the installer trusts, such as temporary plugin files or uninstaller files, and turn that into code execution as SYSTEM. In other words, the weakness is not “the installer runs as admin,” but that the installer’s temp-file handling can let an unprivileged user hijack an elevated install or uninstall flow

#### Common DLLs Seen in NSIS Installers

> Note: Some of these are **official NSIS plugins**, while others are **common third-party plugins** often used by NSIS installers.  
> Seeing one of these DLLs is a clue, but not absolute proof, that an installer uses NSIS. A file path of `C:\Windows\Temp\*.tmp\*.dll` is a strong indication.

| DLL | Typical purpose | Type | Notes |
|---|---|---|---|
| `System.dll` | Calls Win32 APIs and external DLL functions from NSIS scripts | Official NSIS plugin | One of the strongest indicators of NSIS |
| `nsDialogs.dll` | Builds custom installer dialogs and controls | Official NSIS plugin | Common in modern NSIS installers |
| `nsExec.dll` | Executes console commands and captures output | Official NSIS plugin | Often used for silent helper commands |
| `StartMenu.dll` | Lets the user choose a Start Menu folder | Official NSIS plugin | Common in classic installers |
| `LangDLL.dll` | Displays a language selection dialog | Official NSIS plugin | Often appears in multilingual installers |
| `Banner.dll` | Shows banner/progress UI during install steps | Official NSIS plugin | Mostly cosmetic |
| `InstallOptions.dll` | Creates older-style custom pages from INI definitions | Official NSIS plugin | Largely replaced by `nsDialogs.dll` |
| `UserInfo.dll` | Retrieves information about the current user/account | Official NSIS plugin | Used for privilege or account checks |
| `Dialer.dll` | Manages dial-up/network connection behavior | Official NSIS plugin | Mostly legacy |
| `Math.dll` | Provides arithmetic helpers for NSIS scripts | Official NSIS plugin | Less commonly needed in newer scripts |
| `NSISdl.dll` | Downloads files from the internet | Official NSIS plugin | Older download plugin; often replaced by `inetc.dll` |
| `Splash.dll` | Shows a splash screen | Official NSIS plugin | Mostly legacy/cosmetic |
| `AdvSplash.dll` | Shows a more advanced splash screen | Common NSIS plugin | Similar role to `Splash.dll` |
| `BgImage.dll` | Displays a background image in the installer UI | Official / common NSIS plugin | Mostly cosmetic |
| `inetc.dll` | Downloads files over HTTP/FTP | Common third-party NSIS plugin | Very common in web installers |
| `InetLoad.dll` | Downloads files from the internet | Common third-party NSIS plugin | Alternative to `NSISdl.dll` / `inetc.dll` |
| `UAC.dll` | Handles elevation and UAC-related behavior | Common third-party NSIS plugin | Strong NSIS-related clue |
| `AccessControl.dll` | Changes file/folder ACLs and permissions | Common third-party NSIS plugin | Used in admin-sensitive installs |
| `Registry.dll` | Advanced Windows Registry operations | Common third-party NSIS plugin | More capable than built-in registry commands in some cases |
| `ShellLink.dll` | Creates or edits Windows shortcut (`.lnk`) files | Common third-party NSIS plugin | Shortcut management helper |
| `SimpleFC.dll` | Compares files or checks file differences | Common third-party NSIS plugin | Utility/helper plugin |
| `FindProcDLL.dll` | Detects whether a process is running | Common third-party NSIS plugin | Often used before upgrades |
| `KillProcDLL.dll` | Terminates running processes | Common third-party NSIS plugin | Common in uninstallers/updaters |
| `NScurl.dll` | Downloads/transfers data using curl-style functionality | Common third-party NSIS plugin | Newer/more capable network helper |
| `ZipDLL.dll` | Handles ZIP archive extraction or creation | Common third-party NSIS plugin | Archive utility |
| `unzipdll.dll` | Extracts ZIP archives | Common third-party NSIS plugin | Older archive plugin |
| `untgz.dll` | Extracts `.tar.gz` archives | Common third-party NSIS plugin | Less common, but seen in some packages |
| `VPatch.dll` | Applies binary patches/updates | Common NSIS-related plugin | Often used in patch installers |
| `CabDLL.dll` | Works with CAB archives | Common NSIS-related plugin | Mostly seen in older packaging workflows |
| `nsJSON.dll` | Parses or generates JSON data | Common third-party NSIS plugin | More common in modern scripted installers |
| `StdUtils.dll` | General-purpose helper utilities for NSIS | Common third-party NSIS plugin | Often used for OS/version/path helpers |
| `ExecDos.dll` | Executes commands with better control over I/O and waiting | Common third-party NSIS plugin | Alternative/extension to `nsExec.dll` |

#### Stronger NSIS Indicators

The following DLLs are especially suggestive of NSIS:

- `System.dll`
- `nsDialogs.dll`
- `nsExec.dll`
- `LangDLL.dll`
- `StartMenu.dll`
- `NSISdl.dll`
- `inetc.dll`
- `UAC.dll`

#### Caution

Some installers extract these DLLs temporarily into a folder like:

- `$PLUGINSDIR`

So they may appear only at runtime, not next to the installer executable on disk.


### DotLocal Redirection Vulnerabilities
**DotLocal redirection abuse is a Windows DLL hijacking issue where a writable app folder lets an attacker trick a legitimate program into loading a malicious DLL first**

DotLocal redirection vulnerability abuses Windows built-in .local / DotLocal DLL redirection feature. Windows supports DLL redirection by honoring a file or folder named like App.exe.local; when present, the loader checks the executable’s folder or that .local folder first for DLLs, and this can apply even when a full DLL path is specified. Microsoft documents this as a legitimate feature for redirecting DLL loads.

Why it becomes a vulnerability: if an attacker can write into the executable’s directory (User writable paths), or into a temporary extraction directory used by a privileged process, they can create Target.exe.local folder and place a malicious DLL where Windows will prefer it. That turns the feature into a DLL hijacking , so the trusted process loads attacker library instead of the intended library.

#### Manual control
Identified high privileged processes in world writable paths should be investigated if they are vulnerable to DotLocal redirection. If you query for them and find applications. Do the last control using ProcMon to see if the process tries to load libraries from the created .exe.local folder. You can use the GetSxsPath tool to determine the full file path. Procmon should show you NAME NOT FOUND / PATH NOT FOUND events pointing to a .exe.local directory if its vulnerable.

**A good rule of thumb is:**
ProcMon can provide evidence of .local probing, but the absence of a visible .exe.local miss does not prove the app is not susceptible. For comctl32.dll especially, the trace often reflects manifest/SxS binding rather than a simple app-folder DLL searc


#### If a program loads:

`C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60b5254171f9507e\comctl32.dll`

#### Check this:

`C:\Path\To\Application.exe.local\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60b5254171f9507e\comctl32.dll`
**Determine redirection path for SxS DotLocal DLL Hijacking** - https://gist.github.com/rxwx/1717e95e5ec11bea12d33e93a3832508


## Prerequisites
Well configured SYSMON config to catch events that are of interest, like event.code 1, 7, 11 and 13 for the User-writable paths and the mentioned registry hives.
 - https://github.com/SwiftOnSecurity/sysmon-config
 - https://github.com/olafhartong/sysmon-modular

Enabled Advanced auditing for some of the Windows events.

Event ID 4688 (process creation) must be explicitly enabled to log newly created processes. 
By default, it does not capture the command line used to start the process; this feature must be specifically enabled in the security policy.

Scheduled task - 4698 is not enabled by default.


## ACL ⭐
### 🔹 Some Common ACL Principals Covering Logged-In Users

| Principal               | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **Everyone**             | All users, including Guests (and in older Windows versions, even Anonymous Logon). Very broad, usually restricted to read access. |
| **Authenticated Users**  | Any account that has successfully logged in (local or domain). Excludes anonymous users. |
| **BUILTIN\Users**        | The local **Users** group on the machine. Includes all standard (non-admin) local accounts. |
| **INTERACTIVE**          | Any user logged in **locally at the console** (keyboard/session). Useful for differentiating local vs. remote access. |
| **COMPUTERNAME\\Username** | A specific **local account** on that computer (e.g., `LAPTOP01\Bob`). Permissions apply only when that user logs on locally. |
| **DOMAIN\\Username**     | A specific **domain account** (e.g., `CORP\Alice`). Permissions follow the user across all domain-joined machines. |


### 📑 ACL Attributes (Some Of The Interesting To Look Into)

Access Control List (ACL) attributes define what actions a user or group can perform on files or folders.  
Here are some key ones worth noting:

| Attribute | Name / Meaning           | Why It’s Interesting                                                                 |
|-----------|--------------------------|--------------------------------------------------------------------------------------|
| **F**     | Full Access              | Grants **all possible rights** (read, write, execute, delete, change permissions, take ownership). Equivalent to "owner-level" control. |
| **M**     | Modify Access            | Allows reading, writing, and deleting files/folders, but **not changing ACLs** or ownership. Most common for regular users. |
| **W**     | Write-Only Access        | User can **create or modify content** but cannot read it back. Rare, but useful in "drop box" scenarios (e.g., secure file submissions). |
| **WD**    | Write Data / Add File    | Specifically allows **creating or writing to files in a directory**. Essential for being able to add or overwrite files inside a folder. |
| **AD**    | Append Data / Add Subdirectory | On files: append data to the end of a file (cannot overwrite). On folders: create new subdirectories inside. |


## False Positives
#### Do your queries, fine tune them and in the end make alerts of them. 
You may need to do some whitelisting (see below for typical paths in ProgramData). The idea is to query typical user writable paths but it happens that the (files or folders) have correct ACL set. If offensive mindset does not help to escalate privileges - whitelist them.
Filter out the less interesting ones: the ones with correct ACL, randomized file.names (filter out the folder). We want to reduce the noice and have a baseline. Its important to do this after verifying that its not a vulnerability. So you dont miss a Scheduled task that is vulnerable on every client.


## Whitelisting
You will likely need to whitelist the queries. Make your hunt, fine tune the queries and make alerts of them to catch new events that you have not looked into.
##### Will likely need whitelisting:
      C:\ProgramData\Microsoft
      C:\ProgramData\Package Cache
      C:\ProgramData\Packages
      etc.

Other ones that may need whitelisting, which may be common, is hardware related drivers and similar stuff that has randomized names..
      

## Methodology
Dont forget to query in the timespan of your "Log retention period".
A good Methodology is to query in the beginning a short time frame which is progressivly increasing.
1) 1 day
2) 1 week
3) 2 weeks
4) 1 month
5) 2 months
6) etc..

Do you hunt and check the interesting ones and fine tune and whitelist.. in the end make alerts of them to catch new events..

## Tips & Tricks
If a binary replacement is not possible because of correct ACL. Check folder permissions and if you have permissions to write files
check if the executable tries to load any dlls that do not exist. If so, create them and you have your code execution. If binary replacement is not possible because its a running process. Check possible DLL sideloading or check if you as a regular user have permissions to restart the service it self. Another way is to check if you as a regular user can perform a "shutdown" that you escape in last second. A shutdown initiation stops processes and if you break out from it, you may be able to replace the binary of the terminated process. If the service is in Autostart mode and you dont have permissions to start/stop the service, what you can check is if you have SeShutdownPrivilege and if so initiate a reboot with shutdown /r /t 0.

If a service is spawning the process and if its not possible to replace binary, the binary does not try to load any missing DLLs. Dont give up - maybe the path is unquoted and you have write permissions and you can use that?

Build your queries layer on layer.. so check for service/schedule task creations, check for the process creation with parent as services or schedule task related process (svchost.exe with Schedule argument). Its possible that some system creates the service or schedule task but the binary path etc does not exist and the process creation never happens. But the vulnerability is still there and different events can be created related to it.

To reduce query load (performance) and probably whitelisting.. it may be a good idea to have queries separated for clients/servers. So a set of queries only used for the client endpoints and same set used for server endpoints.

The generic process creation by SYSTEM is high value query. It catches alot of scenarios.. besides of services and schtask spawning child processes it also catches msiexec.exe spawning a child process. It also caches if a executable from c:\windows\ccmcache is spawning a child process from a userwritable path. If we where to order executables in vulnerability i would still say that services.exe is related to software misconfigurations and schtasks is more a administrator misconfiguration..

If you have tried all queries and did not got successful. if you want to hunt deeper, and do a litte bit more work - go for every child process of services.exe and schtasks (svchost.exe with Schedule argument), regardless of where. Enumerate the enterprise and look for the ones in typical admin protected paths also (Program Files & Program Files (x86)). Its more common than you think that software vendors mess up the ACL even in typical protected paths. Use the process creation events and the events for services and schedule tasks. For Schedule tasks - query every Command field and Argument field. The argument field may be pointing to a script file in user writable path or C-root. The command fields may be pointing to a binary that has insecure ACL.

## Uninstall processes
Its likely that if a user can trigger an installation, they can also trigger a uninstallation. Uninstall processes are of interest regardles of where the filepath is.
If the ACL is not correct - a binary replacement will likely cause trouble.
Query also for file creation of typical uninstall files by using Sysmon event.code:11.
We want to do this to catch every uninstaller without trusting the process creation events. This is because its not common that users actually do uninstallation of installed applications.. They just dont care about that and therefor it will be easier to miss some uninstall events that exists but never are triggered.

### Example of uninstall process names
#### Common Generic Names

          uninstall.exe – Most generic and widely used.
          unins000.exe, unins001.exe – Common with Inno Setup installers.
          unwise.exe – Often used by older Wise Installer packages.
          uninst.exe – Shortened version, often found in legacy software.
          uninstaller.exe – Slightly longer, descriptive variant.
          remove.exe – Sometimes used for minimal installers.
          setup.exe (with /uninstall or /remove parameter) – Some apps reuse the installer executable for uninstallation.
          appname_uninstall.exe (e.g., chrome_uninstall.exe)
          update.exe (with --uninstall) – Seen with apps like Slack or Discord using Squirrel installers.

#### Patterns Worth Considering

          *_uninstall.exe – Many apps prepend the app name, e.g., teams_uninstall.exe, zoom_uninstall.exe.
          *_cleanup.exe – Removal tools often have cleanup variants, e.g., driver_cleanup.exe.
          *_remover.exe – Another common AV/vendor naming style.

## Script files
### Consider query for the ones in the list
| Extension | Language / Type           | Purpose / Usage                                         | Execution Context                                          |
|-----------|---------------------------|---------------------------------------------------------|------------------------------------------------------------|
| .bat      | Batch Script               | Legacy command-line automation tasks, simple scripts     | `cmd.exe` (Command Prompt)                                  |
| .cmd      | Batch Script (NT style)    | Similar to `.bat`, preferred on NT-based systems         | `cmd.exe` (Command Prompt)                                  |
| .vbs      | VBScript                   | Automation tasks, logon scripts, admin scripts           | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .vbe      | VBScript (encoded)         | Encoded version of `.vbs` for obfuscation              | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .ps1      | PowerShell Script          | Modern Windows automation and configuration tasks       | PowerShell (`powershell.exe`, `pwsh.exe`)                   |
| .js       | JScript                    | Microsoft’s version of JavaScript for WSH tasks          | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .jse      | JScript (encoded)          | Encrypted version of `.js` for obfuscation               | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .wsf      | Windows Script File (XML)  | Mix VBScript, JScript, other scripts in XML format       | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .wsh      | Windows Script Host Settings | Configuration settings for WSH scripts                  | Windows Script Host (`wscript.exe`, `cscript.exe`)          |
| .jar      | Java Archive               | Java applications packaged as a single file             | `java.exe` (console) / `javaw.exe` (no console window)       |
| .hta      | HTML Application (HTA)     | GUI-based Windows scripts using HTML, CSS, and JScript/VBScript | `mshta.exe` (Microsoft HTML Application Host)          |
| .com      | MS-DOS Application / DOS Executable | Legacy executable programs, small command-line utils | Executed directly as a program; on modern Windows, classic 16-bit .com programs run through NTVDM on 32-bit Windows, and are not natively supported on x64/ARM Windows |
| .chm     | Compiled HTML Help          | Offline help/documentation files for Windows programs   | `hh.exe` (Microsoft HTML Help Viewer)                           |

## Startup/Logon scripts

Startup and Logon Scripts (and Shutdown or Logoff) are automation scripts that run (gpscript.exe) automatically on domain-joined computers or when users sign in, and they are commonly deployed using Group Policy Objects (GPOs) from a domain controller in a Windows Active Directory environment.

Startup/Shutdown
- Run as: Local System account (high privileges).

Logon/Logoff
- Run as: Current user (high privileges if administrator).
### Common uses:
- Mapping network drives for all users
- Installing software
- Applying system-wide settings
- Starting or configuring services
- Running scripts or executables

### Registry Hives Affected

When a startup/logon script runs via GPO:

| Hive / Path | Purpose |
|-------------|---------|
| HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon | Tracks user logon scripts, their execution order, status, last run time, and parameters. |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff | Similar tracking for logoff scripts. |
| HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup | Startup scripts (applies to all users) tracking info. |
| HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown | Shutdown scripts info. |

#### Look for User-writable paths for scripts and executables in the child process of gpscript.exe, or writable network shares or genereic (SYSVOL). 
Read the scripts that are run and look if there is any misconfigurations like other User-Writable paths or paths that does not exist or sensitive information. Look for possible used passwords (net use z: \\server\share /user:domain\username password) or other sensitive information. 

**Logon Script Misconfiguration Categories**
- SS1 – Plaintext credentials
- SS2 – Unsafe permissions (modifiable logon script by regular user)
- SS3 – Non-existent shares (which may be creatable by regular user)
- SS4 - Admins with logon scripts

**Logon Script Misconfigurations**

1. SS1 - Plaintext credentials within a logon script
2. SS2 - Unsafe share permissions
3. SS2 - Unsafe file permissions
4. SS2 - Unsafe NETLOGON/SYSVOL permissions
5. SS2 - Unsafe logon script permissions
6. SS2 - Unsafe GPO logon script permissions
7. SS3 - Non-existent shares
8. SS4 - Admins with logon script
9. SS4 - Admins with logon scripts mapped from nonexistent share



## MSIExec / MSI Repairs
##### Our testing did not give any result in escalating privileges in scenarios where we could spawn edge and break out to a cmd prompt. This is probably because chromium based browsers is impersonating the user/restricting rendering process to run as SYSTEM and does not allow internet explorer/edge to spawn cmd or other processes as the SYSTEM user. We believe that if none chromium based browser is installed (like firefox) or older versions. An privilege escalation could be possible if you could spawn such process and break out from that to a command prompt.

If you want to enumerate possible events related to this is to query for msiexec.exe as parent process with cmd.exe OR conhost.exe OR powershell.exe OR pwsh.exe as child process.
Contact the users your query get results from and ask them what they installed/repaired. You can also check event.provider: "MsiInstaller" and event.code: (1033 OR 11707) or similar to get more context about which msi installer was installed around same timestamp.
You could also try this your self in Software Center and install the applications and look for command prompts which you can pause before they dissapear by marking a section in the window. Then break out using same techniques mentioned in the link below.



##### Example query
```
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.parent.name: msiexec.exe AND process.name: (cmd.exe OR conhost.exe OR powershell.exe OR pwsh.exe))
OR
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.parent.name: msiexec.exe AND process.name: (cmd.exe OR conhost.exe OR powershell.exe OR pwsh.exe))
```
- https://cloud.google.com/blog/topics/threat-intelligence/privileges-third-party-windows-installers/


## If you dont have enough telemetry or want to hunt deeper
In situations where available telemetry is limited, researchers can collect deeper host activity using boot logging in Process Monitor. Procmon can capture low-level system activity such as process creation, file access, registry operations, driver loads, and service activity starting very early in the Windows boot process in Microsoft Windows. The captured boot log can be exported to CSV and converted to NDJSON and ingested into a SIEM for further hunting and analysis. This approach can provide additional visibility when investigating privilege escalation or persistence techniques that might not appear in standard logging sources. Check the section procmon for more information.



## Example of some public windows privilege escalation CVEs (permissions → EXE/DLL load/replace)
To show you how common it is with misconfigured third party software.
| CVE           | Vendor / Product           | Path(s) / File(s)                                | Loads as SYSTEM                  | CWE     | Notes                          |
|---------------|----------------------------|--------------------------------------------------|----------------------------------|---------|--------------------------------|
| CVE-2025-42598| Epson Printer Drivers      | C:\ProgramData\EPSON\EPSON <serie> Series Dlls   | spoolsv.exe / PrintIsolationHost.exe | CWE-276 | DLL overwrite → SYSTEM      |
| CVE-2025-64669| Windows Admin Center       | C:\ProgramData\WindowsAdminCenter\Updater        | WindowsAdminCenterUpdater.exe    | CWE-276 | DLL Hijacking                   |
| CVE-2019-19363| Ricoh Printer Drivers      | C:\ProgramData\RICOH_DRV\                        | PrintIsolationHost.exe           | CWE-264*| DLL planting → SYSTEM           |
| CVE-2025-1729 | Lenovo TrackPoint          | C:\ProgramData\Lenovo\TPQM\Assistant             | TPQMAssistant.exe                |         | DLL Hijacking, Schtasks         |
| CVE-2025-47962| Microsoft Windows SDK      | C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin | cryptsp.dll                      | CWE-284 | DLL Hijacking, Service          |
| CVE-2025-11772| Synaptics Fingerprint      | C:\ProgramData\Synaptics\CheckFPDatabase.exe     | WTSAPI32.dll etc                 |         | DLL Hijacking USB Co-Installers |
| CVE-2020-5896 | BIG IP F5 Client           | C:\Windows\Temp\f5tmp\cachecleaner.exe           | cachecleaner.dll                 | CWE-276 | DLL planting → SYSTEM           |
| CVE-2020-13885| Citrix Workspace App       | %PROGRAMDATA%\Citrix\Citrix Workspace ####\webio.dll | Citrix services / uninstall     | CWE-276 | DLL planting → SYSTEM        |
| CVE-2018-17778| SnowAgent                  | C:\Windows\Temp\cpuz143\cpuz143_x64.sys          | snowagent.exe CPUID SDK          |         | SYS file planting → SYSTEM |
| CVE-2026-3991 | Symantec DLP Agent for Windows | C:\VontuDev\workDir\openssl\output\x64\Release\SSL\openssl.cnf | edpa.exe       |         | LPE openssl.cnf |
| CVE-2025-8069 | AWS Client VPN             | C:\usr\local\windows-x86_64-openssl-localbuild\ssl |                                |         | LPE openssl.cnf   |
| CVE-2025-2272 | ForcePoint Endpoint DLP    | C:\usr\local\ssl\openssl.cnf                     | ENdPointClassifier.exe          |          | LPE openssl.cnf   |
| CVE-2025-13176 | ESET Inspect EDR          | C:\src\vcpkg\packages\openssl_x64-windows-static\openssl.cnf | ElConnector.exe     |          | LPE openssl.cnf   | 
| CVE-2024-6975  | Cato Client               | C:\Work\WinVPNClient\ThirdParty\openssl\openssl-3.1.1\VS2022\SSL64\openssl.cnf | winvpnclient.cli.exe  | | LPE openssl.cnf |
| CVE-2023–6338   | Lenovo UDC               | C:\J\w\prod\BUildSIngleReference.......          | UDClientService.exe             |          | LPE openssl.cnf   |
| CVE-2023-41840  | FortiClient Windows OpenSSL component |                                     |                                 | CWE-426 | openssl.cnf       |       
| CVE-2021-21999  | VMWare Workstation tools |                                                  |                                  |         | LPE openssl.cfg  |
| CVE-2020-8224   | Nextcloud windows desktop application | C:\usr\local\ssl\openssl.cnf        | nextcloud.exe                   |          | LPE openssl.cnf   |
| CVE-2020–26050  | SaferVPN                 | C:\etc\ssl\openssl.cnf                           | C:\Program Files (x86)\SaferVPN for Windows\bin\openvpn.exe || LPE openssl.cfg |
| CVE-2019-12572  | PIA Windows service      | C:\etc\ssl\openssl.cnf                           | pia-service.exe                 |          | LPE openssl.cnf   |
| CVE-2024-34474| Clario for Desktop         | C:\ProgramData\Clario\                           | ClarioService.exe                | CWE-276 | Loads DLLs from ProgramData     |
| CVE-2022-34043| NoMachine (Windows)        | C:\ProgramData\NoMachine\var\uninstall\          | Uninstaller                      | CWE-732 | DLL hijack in uninstall folder  |
| CVE-2020-15145| Composer-Setup (Windows)   | C:\ProgramData\ComposerSetup\bin\composer.bat (+ DLLs) | Maintenance/repair actions     | CWE-276 | Writable bin → LPE          |
| CVE-2019-14935| 3CX Phone for Windows      | %PROGRAMDATA%\3CXPhone for Windows\PhoneApp\     | Startup / elevated context       | CWE-732 | Everyone:Full Control           |
| CVE-2024-54131| Kolide Launcher            | C:\ProgramData\Kolide\Launcher-[ID]\data\        | Launcher service                 | CWE-276 | Weak perms → DLL load           |
| CVE-2021-28098| Forescout SecureConnector  | %PROGRAMDATA%\ForeScout SecureConnector\         | SecureConnector service          | CWE-264*| Writable log → symlink → SYSTEM |
| CVE-2019-15752| Docker Desktop (Windows)   | %ProgramData%\DockerDesktop\version-bin\docker-credential-wincred.exe | Docker auth flow      | CWE-276 | EXE planting → SYSTEM |
| CVE-2022-39959| Panini Everest Engine      | %PROGRAMDATA%\Panini\Everest Engine\EverestEngine.exe | Engine service (SYSTEM)        | CWE-276 | Unquoted path → EXE planting |
| CVE-2018-10204| PureVPN (Windows)          | %PROGRAMDATA%\purevpn\config\config.ovpn         | openvpn.exe (service)            | CWE-276 | Writable config → DLL load      |
| CVE-2020-27643| 1E Client (Windows)        | %PROGRAMDATA%\1E\Client\                         | Client service                   | CWE-276 | Writable dir → LPE              |
| CVE-2020-1985 | Palo Alto Secdo Agent      | C:\ProgramData\Secdo\Logs\                       | Secdo service                    | CWE-276 | Incorrect default perms         |
| CVE-2024-36495| Faronics WINSelect         | C:\ProgramData\WINSelect\WINSelect.wsd / Faronics\StorageSpace\WS\WINSelect.wsd | WINSelect service | CWE-276 | Config writable → LPE|
| CVE-2024-20656| Visual Studio Setup WMI    | C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe | Repair action (SYSTEM)      | CWE-276 | Replace binary → SYSTEM |
| CVE-2025-3224 | Docker Desktop (Windows)   | C:\ProgramData\Docker\config\                    | Updater (high priv)              | CWE-276 | Creatable/deletable path → LPE   |


