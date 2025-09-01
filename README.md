# Offensive SIEM
## Coming soon
Release of some of the presentation material and queries will happen after 12 september 2025.
Meanwhile check out this outstanding webinar about windows local privilege escalation which will assist you further on.

### Webinar - Windows Client Privilege Escalation - a must to watch, specially the ACL parts.
https://www.youtube.com/watch?v=EG2Mbw2DVnU&t=2411s

### Other related to Windows Privilege Escalation.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

### Example of interesting areas to look into that we have not covered.
* weak passwords in command_line - that are not following best practices / policies
* weak passwords in registry  - that are not following best practices / policies
* AlwaysInstallElevated in Registry
* Windows Privileges - Look at 4672 (logon with special privileges) And 4704/4705 (assignment/removal of rights)
* etc..
* Do not assume that Program Files and similar admin-protected directories always have correct ACLs (Access Control Lists). It does happen that applications set incorrect default permissions and are far too permissive. CWE-732, CWE-284, CWE-276

### Other types of vulnerabilties
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
* AD attributes (example event.code:"5136" and Attribute:"msDS-KeyCredentialLink") that are commonly abused. Find misconfigurations and harden AD. 
etc.. etc..

### Software installed in C-root drive. (not covered in presentation)
Make a process creation query using event.code 1 from SYSMON OR event.code 4688 (or the event.codes for services, schedule tasks, DLL load from C-root subfolders)
Look for applications that are installed in C:\ root drive

##### example: 
               C:\myapplication\myapplication.exe
               C:\myapp\subfolder\myapp.exe
               C:\SoftwareCompany\software.exe
               C:\myapplication\myapplication.dll
               C:\myapp\subfolder\myapp.dll
               C:\SoftwareCompany\software.dll
               

The issue with applications that are installed in C-root folder is that it has per default incorrect ACL permissions which allows Authenticated Users to modify the folder and its files. If the Software installation does not change the ACL in the installation process,
Its likely a privilege escalation (confirm it) if a service or another process is spawning a high privileged process (myapplication.exe OR myapp.exe) from one of the installation paths in C-root.
#### Missed the chance of a Microsoft CVE - someone found it before: https://neodyme.io/en/advisories/cve-2025-47962/

### Services - use offensive mindset
Gives you an idea of which event codes to use what you will see in the event code it self.
https://detect.fyi/threat-hunting-suspicious-windows-service-names-2f0dceea204c

### Schedule taks - use offensive mindset (we only covered SYSTEM user execution but Admin users are also of interest)
Gives you and idea of which event codes to use and what you will see in the event code it self.
https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks

## Prerequisites
Well configured SYSMON config to catch events that are of interest, like event.code 1, 7, 11.

Enabled Advanced auditing for some of the Windows events.
For an example, process creation 4688 will likely need it to catch parent process and not only the parent pid.


## ACL
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


## Whitelisting
You will likely need to whitelist the queries. Make your hunt, fine tune the queries and make alerts of them to catch new events that you have not looked into.
##### Will likely need whitelisting:
C:\ProgramData\Microsoft
C:\ProgramData\Package Cache
C:\ProgramData\Packages
etc.





