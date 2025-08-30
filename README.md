# sec_t

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

### Other types of vulnerabilties
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
* AD attributes (example event.code:"5136" and Attribute:"msDS-KeyCredentialLink") that are commonly abused. Find misconfigurations and harden AD. 
etc.. etc..

#### Software installed in C-root drive. (not covered in presentation)
Make a process creation query using event.code 1 from SYSMON OR event.code 4688 (or the event.codes for services, schedule tasks)
Look for applications that are installed in C:\ root drive
##### example: 
               C:\myapplication\myapplication.exe
               C:\myapp\subfolder\myapp.exe
               C:\SoftwareCompany\software.exe

The issue with applications that are installed in C-root folder has per default incorrect ACL permissions which allows Authenticated Users to modify the folder and its files.
Its likely a privilege escalaion (confirm it) if a service or another process is spawning a high privileged process (myapplication.exe OR myapp.exe) from one of the installation paths i C-root.



#### Services - use offensive mindset
Gives you an idea of which event codes to use what you will see in the event code it self.
https://detect.fyi/threat-hunting-suspicious-windows-service-names-2f0dceea204c

#### Schedule taks - use offensive mindset (we only covered SYSTEM user execution but Admin users are also of interest)
Gives you and idea of which event codes to use and what you will see in the event code it self.
https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks






