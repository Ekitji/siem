# Offensive SIEM
## Queries
See above - queries.md file

## Ping us if/when you find something 
We hope that you liked the presentation. Ping us if you (i would say when you) find vulnerabilities by using this method. A simple message like "one of your queries cathed good stuff".. is more then enough :) do it by commiting to the ping.md file or contact us in alternative ways! We would be happy to share your success!

### General information
The repo will assist you in having offensive mindset. 

Repo is to share the material and queries that we talked about in our presentation:


⭐ https://www.youtube.com/watch?v=5nfL_4ek4dY

We have included the most interesting ACL related parts and have tips & tricks.

Check out the outstanding webinars about windows local privilege escalation and windows endpoint misconfigurations which will assist you further on. There are more areas to look into.. This is only the starting point. If you build good queries in other areas - please share it with us so more in the community can use them.

The queries with ⭐ mark is extra highly relevant.
The topics down below with ⭐ is really good content.


### Webinar
#### Windows Client Privilege Escalation ⭐
a must to watch, specially the ACL for binaries, services and schedule tasks. 
- https://www.youtube.com/watch?v=EG2Mbw2DVnU
#### Spencers Windows Endpoint Misconfigs ⭐
Topic 2 (Insecurely installed/conf Software) And Topic 5 (Insecure Services And Tasks) - passsword: P3yGQ+1y
- https://go.spenceralessi.com/windowsmisconfigsreplay

### Other related to Windows Privilege Escalation.
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html  
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/ 

### Example of interesting areas to look into that we have not covered.
* weak passwords in command_line - that are not following best practices / policies
* weak passwords in registry  - that are not following best practices / policies
* AlwaysInstallElevated in Registry
* Windows Privileges - Look at 4672 (logon with special privileges) And 4704/4705 (assignment/removal of rights)
* etc..
* Do not assume that Program Files and similar admin-protected directories always have correct ACLs (Access Control Lists). It does happen that applications set incorrect default permissions and are far too permissive. CWE-732, CWE-284, CWE-276

### Other types of vulnerabilities
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
* AD attributes (example event.code:"5136" and Attribute:"msDS-KeyCredentialLink") that are commonly abused. Find misconfigurations and harden AD.
* Linux
etc.. etc..

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

### Schedule taks - use offensive mindset (we only covered SYSTEM user execution but Admin users are also of interest) ⭐
Gives you and idea of which event codes to use and what you will see in the event code it self.
- https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks

## Prerequisites
Well configured SYSMON config to catch events that are of interest, like event.code 1, 7, 11.

Enabled Advanced auditing for some of the Windows events.
For an example, process creation 4688 will likely need it to catch parent process and not only the parent pid.


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


## Whitelisting
You will likely need to whitelist the queries. Make your hunt, fine tune the queries and make alerts of them to catch new events that you have not looked into.
##### Will likely need whitelisting:
      C:\ProgramData\Microsoft
      C:\ProgramData\Package Cache
      C:\ProgramData\Packages
      etc.


## Tips & Tricks
If a binary replacement is not possible because of correct ACL. Check folder permissions and if you have permissions to write files
check if the executable tries to load any dlls that do not exist. If so, create them and you have your code execution.

If a service is spawning the process and if its not possible to replace binary, the binary does not try to load any missing DLLs. Dont give up - maybe the path is unquoted and you can use that?

Build your queries layer on layer.. so check for service/schedule task creations, check for the process creation with parent as services or schtasks. Its possible that some system creates the service or schedule task but
the binary path etc does not exist and the process creation never happens. But the vulnerability is still there.

## Uninstall processes
Its likely that if a user can trigger an installation, they can also trigger a uninstallation. Uninstall processes are of interest regardles of where the filepath is.
If the ACL is not correct - a binary replacement will likely cause trouble.
query also for file creation of typical uninstall files by using Sysmon event.code:11. 

### Example of uninstall process names
We are only covering unins*
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


## Example of some public windows privilege escalation CVEs (permissions → EXE/DLL load/replace)
To show you how common it is with misconfigured third party software.
| CVE           | Vendor / Product           | Path(s) / File(s)                                | Loads as SYSTEM                  | CWE     | Notes                          |
|---------------|----------------------------|--------------------------------------------------|----------------------------------|---------|--------------------------------|
| CVE-2025-42598| Epson Printer Drivers      | C:\ProgramData\EPSON\EPSON <serie> Series Dlls        | spoolsv.exe / PrintIsolationHost.exe | CWE-276 | DLL overwrite → SYSTEM      |
| CVE-2019-19363| Ricoh Printer Drivers      | C:\ProgramData\RICOH_DRV\                        | PrintIsolationHost.exe           | CWE-264*| DLL planting → SYSTEM           |
| CVE-2025-1729 | Lenovo TrackPoint          | C:\ProgramData\Lenovo\TPQM\Assistant             | TPQMAssistant.exe                |         | DLL Hijacking, Schtasks         |
| CVE-2025-47962 | Microsoft Windows SDK     | C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin  | cryptsp.dll                     | CWE-284  | DLL Hijacking, Service         |
| CVE-2020-13885| Citrix Workspace App       | %PROGRAMDATA%\Citrix\Citrix Workspace ####\webio.dll | Citrix services / uninstall     | CWE-276 | DLL planting → SYSTEM           |
| CVE-2024-34474| Clario for Desktop         | C:\ProgramData\Clario\                           | ClarioService.exe                | CWE-276 | Loads DLLs from ProgramData     |
| CVE-2022-34043| NoMachine (Windows)        | C:\ProgramData\NoMachine\var\uninstall\          | Uninstaller                      | CWE-732 | DLL hijack in uninstall folder  |
| CVE-2020-15145| Composer-Setup (Windows)   | C:\ProgramData\ComposerSetup\bin\composer.bat (+ DLLs) | Maintenance/repair actions     | CWE-276 | Writable bin → LPE              |
| CVE-2019-14935| 3CX Phone for Windows      | %PROGRAMDATA%\3CXPhone for Windows\PhoneApp\     | Startup / elevated context       | CWE-732 | Everyone:Full Control           |
| CVE-2024-54131| Kolide Launcher            | C:\ProgramData\Kolide\Launcher-[ID]\data\        | Launcher service                 | CWE-276 | Weak perms → DLL load           |
| CVE-2021-28098| Forescout SecureConnector  | %PROGRAMDATA%\ForeScout SecureConnector\         | SecureConnector service          | CWE-264*| Writable log → symlink → SYSTEM |
| CVE-2022-31262| GOG Galaxy (Windows)       | %ProgramData%\GOG.com\                           | Galaxy service                   | CWE-276 | Service EXE replacement         |
| CVE-2019-15752| Docker Desktop (Windows)   | %ProgramData%\DockerDesktop\version-bin\docker-credential-wincred.exe | Docker auth flow              | CWE-276 | EXE planting → SYSTEM           |
| CVE-2022-39959| Panini Everest Engine      | %PROGRAMDATA%\Panini\Everest Engine\EverestEngine.exe | Engine service (SYSTEM)        | CWE-276 | Unquoted path → EXE planting    |
| CVE-2018-10204| PureVPN (Windows)          | %PROGRAMDATA%\purevpn\config\config.ovpn         | openvpn.exe (service)            | CWE-276 | Writable config → DLL load      |
| CVE-2020-27643| 1E Client (Windows)        | %PROGRAMDATA%\1E\Client\                         | Client service                   | CWE-276 | Writable dir → LPE              |
| CVE-2020-1985 | Palo Alto Secdo Agent      | C:\ProgramData\Secdo\Logs\                       | Secdo service                    | CWE-276 | Incorrect default perms          |
| CVE-2024-36495| Faronics WINSelect         | C:\ProgramData\WINSelect\WINSelect.wsd / Faronics\StorageSpace\WS\WINSelect.wsd | WINSelect service            | CWE-276 | Config writable → LPE            |
| CVE-2024-20656| Visual Studio Setup WMI    | C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe | Repair action (SYSTEM)      | CWE-276 | Replace binary → SYSTEM          |
| CVE-2025-3224 | Docker Desktop (Windows)   | C:\ProgramData\Docker\config\                    | Updater (high priv)              | CWE-276 | Creatable/deletable path → LPE   |


