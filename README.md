# sec_t

## Offensive SIEM
Coming soon

Release of some of the presentation material and queries will happen after 12 september 2025.

Meanwhile check out this outstanding webinar about windows local privilege escalation which will assist you further on.

### Webinar - Windows Client Privilege Escalation - a must to watch, specially the ACL parts.
https://www.youtube.com/watch?v=EG2Mbw2DVnU&t=2411s

### Other related to Windows Privilege Escalation.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

* weak passwords in command_line - that are not following best practices / policies
* weak passwords in registry  - that are not following best practices / policies
* AlwaysInstallElevated in Registry
* Windows Privileges - Look at 4672 (logon with special privileges) And 4704/4705 (assignment/removal of rights)
* etc..

### Other types of vulnerabilties to search for
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
* AD attributes (example event.code:"5136" and Attribute:"msDS-KeyCredentialLink") that are commonly abused. Find misconfigurations and harden AD. 
etc.. etc..



#### Services - use offensive mindset
Gives you an idea of which event codes to use what you will see in the event code it self.
https://detect.fyi/threat-hunting-suspicious-windows-service-names-2f0dceea204c

#### Schedule taks - use offensive mindset
Gives you and idea of which event codes to use and what you will see in the event code it self.
https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks


