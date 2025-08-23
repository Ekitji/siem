# sec_t

## Offensive SIEM
Coming soon

Release of some of the presentation material and queries will happen after 12 september 2025.

Meanwhile check out this outstanding webinar about windows local privilege escalation which will assist you further on.

### Webinar - Windows Client Privilege Escalation
https://www.youtube.com/watch?v=EG2Mbw2DVnU&t=2411s

### Other related to Windows Privilege Escalation.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

* weak passwords in command_line - that are not following best practices / policies
* weak password in registry  - that are not following best practices / policies
* AlwaysInstallElevated in Registry
* Windows Privileges - Look at 4672 (logon with special privileges) And 4704/4705 (assignment/removal of rights)
* etc..

### Other types of vulnerabilties to search for
* Search in webserver logs for parameters (language=en.html) that shows file inclusion to test for LFI/RFI
* Search for application logs for SQL related errors that shows errors on bad charachters..
etc.. etc..
