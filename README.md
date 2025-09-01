# Offensive SIEM
## Coming soon
Release of some of the presentation material and queries will happen after 12 september 2025.
Meanwhile check out this outstanding webinar about windows local privilege escalation which will assist you further on.

### Webinar - Windows Client Privilege Escalation - a must to watch, specially the ACL parts. ⭐
- https://www.youtube.com/watch?v=EG2Mbw2DVnU&t=2411s

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
etc.. etc..

### Software installed in C-root drive. (not covered in presentation) ⭐
Make a process creation query using event.code 1 from SYSMON OR event.code 4688 (or the event.codes for services, schedule tasks, DLL load from C-root subfolders)
Look for applications that are installed in C:\ root drive

##### example: 
          C:\myapplication\myapplication.exe
          C:\myapp\subfolder\myapp.exe
          C:\SoftwareCompany\software.exe
          C:\myapplication\myapplication.dll
          C:\myapp\subfolder\myapp.dll
          C:\SoftwareCompany\software.dll
               

The issue with applications that are installed in C-root folder is that it has per default incorrect ACL permissions which allows Authenticated Users to modify (M) the folder and its files. If the Software installation does not correct the ACL in the installation process,
If so - you will likely have a privilege escalation (confirm it) if a service or another process is spawning a high privileged process (ex. myapplication.exe OR myapp.exe) from one of the installation paths in C-roots subfolder.
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


## Windows privilege escalation CVEs (permissions → EXE/DLL load/replace)
CVE	App / Vendor	Windows path involved (as documented)	What loads/runs as SYSTEM	CWE (per source)	Notes & sources
CVE-2025-42598	Epson Printer Drivers (multiple models)	Path not disclosed by vendor (driver-managed DLLs). Typical printer DLLs live under C:\Windows\System32\spool\drivers\...; many Epson installs also use C:\ProgramData\Epson\...	Printer driver DLLs are loaded by the print stack (spoolsv.exe/PrintIsolationHost.exe)	CWE-276 (JVN)	Official advisories confirm DLL overwrite → SYSTEM code exec on non-English installs; JVN tags CWE-276. Vendor/JVN do not publish an exact path. Example write-ups show DLL placement under spool driver dirs. 
Epson
jvn.jp
NVD
Epson Download 4
Ameeba

CVE-2019-19363	Ricoh printer drivers	C:\ProgramData\RICOH_DRV\ (DLL overwrite)	PrintIsolationHost.exe (SYSTEM) loads vendor DLL	(permissions flaw)	Public exploit shows DLL planted in ProgramData and loaded by PrintIsolationHost, yielding SYSTEM. 
Rapid7
Exploit Database
pentagrid.ch

CVE-2020-13885	Citrix Workspace App (Windows)	%PROGRAMDATA%\Citrix\Citrix Workspace ####\webio.dll	SYSTEM service during uninstall/repair loads DLL	(insecure perms)	NVD notes insecure perms for this ProgramData path enabling DLL planting. 
NVD

CVE-2024-34474	Clario for Desktop (Windows)	%PROGRAMDATA%\Clario\ and %PROGRAMDATA%\Clario\Engines\	ClarioService.exe (SYSTEM) attempts DLL loads from ProgramData	(weak perms)	NVD and the PoC repo state weak perms + DLL load from ProgramData as SYSTEM. 
NVD
GitHub

CVE-2022-34043	NoMachine for Windows	C:\ProgramData\NoMachine\var\uninstall\	Uninstaller path abused for DLL hijacking	(permissions)	Incorrect folder permissions allow DLL hijack → code exec. 
NVD
Incibe

CVE-2020-15145	Composer-Setup for Windows	C:\ProgramData\ComposerSetup\bin\ (e.g., malicious DLL in this folder)	SYSTEM context during maintenance actions	(permissions / planting)	NVD notes attacker-controlled DLL in this ProgramData bin → SYSTEM. 
NVD

CVE-2019-14935	3CX Phone for Windows	%PROGRAMDATA%\3CXPhone for Windows\PhoneApp\	Startup link / elevated context	(insecure perms)	Folder grants Everyone full control → LPE. 
NVD
CVE Details

CVE-2024-54131	Kolide Launcher (Windows agent)	ProgramData (launcher “root directory” after 1.5.3)	Launcher (SYSTEM)	(weak perms)	Moving upgraded binaries to ProgramData introduced lax ACLs enabling LPE. 
NVD

CVE-2021-28098	Forescout SecureConnector	%PROGRAMDATA%\ForeScout SecureConnector\ log file	SecureConnector service (admin/SYSTEM) follows symlink	(permissions / link)	Writable log path + symlink → write into privileged location → LPE. 
NVD

CVE-2022-31262	GOG Galaxy 2.x (Windows)	%ProgramData%\GOG.com\ service files	Galaxy service (SYSTEM) EXE replacement	(insufficient folder perms)	Writable ProgramData lets replacing service executable → SYSTEM. 
NVD

CVE-2019-15752	Docker Desktop (Windows)	%ProgramData%\DockerDesktop\version-bin\docker-credential-wincred.exe	Elevated Docker auth flow executes planted EXE	(permissions / planting)	Low-priv user can drop trojan wincred.exe in ProgramData → elevation. 
NVD

CVE-2022-39959	Panini Everest Engine	%PROGRAMDATA%\Panini\Everest Engine\EverestEngine.exe (unquoted path); attacker can create %PROGRAMDATA%\Panini\Everest.exe	Engine service (SYSTEM)	(unquoted path → EXE planting)	Service path & perms allow ProgramData EXE pre-loading → SYSTEM. 
NVD

CVE-2018-10204	PureVPN (Windows)	%PROGRAMDATA%\purevpn\config\config.ovpn	openvpn.exe runs with service context; plugin path in writable config → DLL load	(insecure perms)	Everyone-writable config lets attacker force a plugin DLL load with elevated rights. 
NVD

CVE-2020-27643	1E Client (Windows)	%PROGRAMDATA%\1E\Client\	Client service (SYSTEM)	(CWE remapped; path exploitation)	Writable ProgramData directory → LPE per vendor/NVD advisory. 
NVD

CVE-2020-1985	Palo Alto Networks Secdo (Windows)	C:\ProgramData\Secdo\Logs\	Secdo components (SYSTEM)	CWE-276	Vendor & NVD: incorrect default perms allow overwrites → LPE. 
security.paloaltonetworks.com
NVD

CVE-2024-36495	Faronics WINSelect	C:\ProgramData\WINSelect\WINSelect.wsd and C:\ProgramData\Faronics\StorageSpace\WS\WINSelect.wsd	WINSelect runs with elevated privileges	(weak perms)	Everyone R/W to config → abuse to neutralize protection and pivot; NVD lists precise paths. 
NVD
SEC Consult

CVE-2024-20656	Visual Studio Setup WMI provider (Windows)	C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe	Repair action runs as SYSTEM	(permissions / replace binary)	Blog PoC swaps MofCompiler.exe under ProgramData to get SYSTEM. 
MDSec

CVE-2025-3224	Docker Desktop for Windows (update)	C:\ProgramData\Docker\config\	Updater (high priv) deletes under this path	(permissions / create-then-abuse)	ProgramData is user-creatable; updater’s high-priv ops can be abused → SYSTEM. 
NVD

