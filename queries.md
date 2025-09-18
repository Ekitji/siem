
# Services

## Potential Local Privilege Escalation - Service Executables in User-Writable Paths
```
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*)) OR (event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
```

## Potential Local Privilege Escalation - Service Created in User-Writable Path
#### Event.code 7045 query catches also none SYSTEM services. 
```
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.logon.id: 0x3e7 AND winlog.event_data.ServiceFileName: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*)) OR (event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*))
```

## Potential Local Privilege Escalation - Unquoted Service Path
#### Check file path if it contains spaces and if so, check ACL for the folders if you can write files to them.
```
((event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath:*\ * AND NOT winlog.event_data.ImagePath:\"* ) OR (event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.event_data.ServiceFileName:*\ * AND NOT winlog.event_data.ServiceFileName:\"*)) AND NOT winlog.event_data.ServiceFileName: (C\:\\WINDOWS\\system32\\* OR C\:\\WINDOWS\\System32\\* OR C\:\\Windows\\system32\\* OR C\:\\Windows\\System32\\* OR C\:\\windows\\system32\\* OR \%SystemRoot\%\\System32\\* OR 
C\:\\windows\\System32\\*) AND NOT winlog.event_data.ImagePath: (C\:\\WINDOWS\\system32\\* OR \%SystemRoot\%\\System32\\* OR C\:\\windows\\system32\\*)
```


# Schedule Tasks

## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as SYSTEM
#### User-Writable Paths in the Arguments
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
#### User-Writable Paths in the Binary path
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
## Potential Local Privilege Escalation - Scheduled Task Binaries from User-Writable Path
#### Use event.code 101 to get User Context → the account under which the task is actually running as (if its the SYSTEM user)
```
(event.provider: "Microsoft-Windows-TaskScheduler" AND event.code: 20*  AND  winlog.event_data.ActionName: (*ProgramData* OR *C\:\\Users\\*) AND NOT winlog.event_data.TaskName: \\Microsoft\\*)
```


# DLL Hijacking

## Potential Local Privilege Escalation - Generic DLL Load from User-Writable Paths ⭐
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*) AND file.extension: (dll OR DLL))
```

## Potential Local Privilege Escalation - Printer DLL Load from User-Writable Paths
```
((event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND process.name: (PrintIsolationHost.exe OR spoolsv.exe)) AND NOT file.path: (C\:\\Windows\\System32\\* OR  C\:\\Program\ Files*))
```

## Potential Local Privilege Escalation - DLL Load from Temp Directory
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND file.path: (C\:\\Windows\\Temp\\*) AND file.extension: (dll OR DLL))
```


# Centralized Application Deployment

## Potential Local Privilege Escalation - Process Creation by SYSTEM in User-Writable Paths ⭐
#### Catches also none Centralized application deployments, its more a generic query that also catches schtasks or services as parent process.
```
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
OR
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
```

## Potential Local Privilege Escalation - Uninstall Process Creation
#### Add other typical uninstall process.names to the query, you can read the README.MD to get more examples.
```
process.name: (uninstall.exe OR Uninstall.exe OR unins.exe OR unins000.exe OR unins001.exe OR unwise.exe OR uninst.exe OR uninstaller.exe OR remove.exe OR *_uninstall.exe OR *_cleanup.exe OR *_remover.exe)
```

## Potential Local Privilege Escalation - Uninstall File Creation by SYSTEM user
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 11 AND user.name: SYSTEM AND file.name: uninstall.exe OR file.name: (Uninstall.exe OR unins.exe OR unins000.exe OR unins001.exe OR unwise.exe OR uninst.exe OR uninstaller.exe OR remove.exe OR *_uninstall.exe OR *_cleanup.exe OR *_remover.exe)
```


# Scripts

## Potential Local Privilege Escalation - Script Files Created by SYSTEM in User-Writable Paths
```
(event.provider: Microsoft-Windows-Sysmon
AND event.code: 11 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*) AND file.extension: (cmd OR bat OR ps1 OR vbs))
```

## Potential Local Privilege Escalation - BAT Files Executed from ProgramData ⭐
#### Dont forget to create the query for powershell + ps1 and other script engines/files, will likely also catch logon scripts.
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe)
(event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe)
```


# C-Root Folder

## Potential local Privilege escalation vulnerability found - Process Creation by SYSTEM in C-Root subfolder ⭐
```
((event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND winlog.event_data.MandatoryLabel: "S-1-16-16384") OR
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System))
AND process.executable.wildcard: (C\:\\*) AND NOT
process.executable.wildcard: (C\:\\Program\ Files* OR C\:\\Windows* OR C\:\\Users* OR C\:\\ProgramData* )
```

## Potential local Privilege escalation vulnerability found - DLL Load by SYSTEM in C-Root subfolder
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 7 AND user.name: SYSTEM AND NOT file.path.wildcard: (C\:\\Program\ Files* OR C\:\\Windows* OR C\:\\Users* OR C\:\\ProgramData*)
```
