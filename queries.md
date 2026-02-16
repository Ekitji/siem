
# Services

## Potential Local Privilege Escalation - Service Created in User-Writable Path
#### Event.code 7045 query catches also none SYSTEM services. 
```
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.logon.id: 0x3e7 AND winlog.event_data.ServiceFileName: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*)) OR (event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*))
```

## Potential Local Privilege Escalation - Service Executables in User-Writable Paths
```
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*)) OR (event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
```


## Potential Local Privilege Escalation - Unquoted Service Path
#### Check file path if it contains spaces and if so, check ACL for the folders if you can write files to them.
```
((event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath:*\ * AND NOT winlog.event_data.ImagePath:\"* ) OR (event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.event_data.ServiceFileName:*\ * AND NOT winlog.event_data.ServiceFileName:\"*)) AND NOT winlog.event_data.ServiceFileName: (C\:\\WINDOWS\\system32\\* OR C\:\\WINDOWS\\System32\\* OR C\:\\Windows\\system32\\* OR C\:\\Windows\\System32\\* OR C\:\\windows\\system32\\* OR \%SystemRoot\%\\System32\\* OR 
C\:\\windows\\System32\\*) AND NOT winlog.event_data.ImagePath: (C\:\\WINDOWS\\system32\\* OR \%SystemRoot\%\\System32\\* OR C\:\\windows\\system32\\*)
```

## Potential Local Privilege Escalation - Registry Service Executables in User-Writable Paths
#### You need to identify what user the service is running as
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: (12 OR 13 OR 14) AND winlog.event_data.TargetObject: HKLM\\System\\CurrentControlSet\\Services\\* AND winlog.event_data.Details: (*ProgramData* OR *C\:\\Users*) AND winlog.event_data.Details: *.\exe*
```

## Potential Local Privilege Escalation - Registry Unquoted Service Path
#### You need to identify what user the service is running as and if there is spaces in the path
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: (12 OR 13 OR 14) AND winlog.event_data.TargetObject: HKLM\\System\\CurrentControlSet\\Services\\* AND winlog.event_data.Details: (*Program \Files*) AND NOT winlog.event_data.Details: \"*
```



# Schedule Tasks

## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as SYSTEM
#### User-Writable Paths in the Arguments (SYSTEM User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
#### User-Writable Paths in the Binary path (SYSTEM User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
#### C-Root Paths in the Arguments (SYSTEM User) -  may also be interesting to query fo D:\, E:\ etc. - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\*) AND NOT winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Program\ Files* OR C\:\\Users\\* OR C\:\\Windows\\*) AND message: *HighestAvailable*)
```

## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as Administrator
### "Highest available" only elevates if the task’s run-as account is an Administrator. If the run-as account is a standard user, there’s no higher integrity to elevate to, so the task runs at the user’s normal Medium integrity—regardless of the “Run with highest privileges” checkbox
#### User-Writable Paths in the Arguments (Administrator User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND NOT winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
#### User-Writable Paths in the Binary path (Administrator User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND NOT winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```
#### C-Root Paths in the Arguments (Administrator User) -  may also be interesting to query for D:\, E:\ etc. - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND NOT winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\*) AND NOT winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Program\ Files* OR C\:\\Users\\* OR C\:\\Windows\\*) AND message: *HighestAvailable*)
```

## Potential Local Privilege Escalation - Scheduled Task executed in a elevated state (Administrator) - Sysmon
#### Uses Sysmons event.code 1 to catch High integrity events, checking command_line will catch binary & arguments pointing to user writeable paths. May be also interesting to query and catch events in C:\ roots subfolders.
```
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND process.parent.name: svchost.exe AND process.parent.args: Schedule AND winlog.event_data.IntegrityLevel: High AND process.command_line: (*ProgramData* OR *Users* OR *Temp* OR *Tmp*))
```
## Potential Local Privilege Escalation - Scheduled Task executed in a elevated state (Administrator)
#### Uses Windows event.code: 4688 - checking command_line will catch binary & arguments pointing to user writeable paths. May be also interesting to query and catch events in C:\ roots subfolders.
```
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-12288" AND process.parent.name: svchost.exe AND process.parent.args: Schedule AND process.command_line: (*ProgramData* OR *Users* OR *Temp* OR *Tmp*))
```

## Potential Local Privilege Escalation - Scheduled Task Binaries from User-Writable Path
#### Use event.code (101 OR 102 OR 106) AND winlog.event_data.UserContext → the account under which the task is actually running as (if its the SYSTEM user)
```
(event.provider: "Microsoft-Windows-TaskScheduler" AND event.code: 20*  AND  winlog.event_data.ActionName: (*ProgramData* OR *C\:\\Users\\*) AND NOT winlog.event_data.TaskName: \\Microsoft\\*)
```

## Potential Local Privilege Escalation - Scheduled Task with User-Writable Path in Working Directory (Start in setting)
#### Generic query to only catch when Working Directory is set to a User-Writable path. Check winlog.event_data.TaskContent for more context and if its a privilege escalation path.
##### This query will show you scheduled tasks that has for an example powershell as the binary, and the command is "Start-Process -WindowsStyle Hidden task.bat" Where task.bat is a batch file and the location of it is set in the schedule task by using "Start in" to set the "WorkingDirectory"
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND message: *WorkingDirectory*) AND message: (*ProgramData* OR C\:\\Users\\* OR *Temp*))
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
#### Dont forget to create the query for powershell + ps1 and other script engines/files, will likely also catch schtask scripts.
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
process.executable.wildcard: (C\:\\Program\ Files* OR C\:\\Windows\\* OR C\:\\Users\\* OR C\:\\ProgramData\\* )
```

## Potential local Privilege escalation vulnerability found - DLL Load by SYSTEM in C-Root subfolder
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 7 AND user.name: SYSTEM AND NOT file.path.wildcard: (C\:\\Program\ Files* OR C\:\\Windows\\* OR C\:\\Users\\* OR C\:\\ProgramData\\*)
```

# Arbitrary File delete
## Potential Arbitrary File delete by SYSTEM in User writable paths
```
(event.provider: Microsoft-Windows-Sysmon AND user.name: SYSTEM AND event.code: (23 OR 26) AND file.path: (C\:\\Users\\* OR C\:\\ProgramData\\* OR C\:\\Windows\\Temp\\*)
```
## Potential Arbitrary File delete by SYSTEM in C-Root subfolder
```
(event.provider: Microsoft-Windows-Sysmon AND user.name: SYSTEM AND event.code: (23 OR 26) AND file.path: (C\:\\*) AND NOT file.path: (C\:\\Users\\* OR C\:\\ProgramData\\* OR C\:\\Program\ Files* OR C\:\\Windows\\*)
```

# Other Queries - Layer on Layer coverage
## Potential Local Privilege Escalation - Process Terminated by SYSTEM in User-Writable Paths
#### Will also give you an idea for the process creation query when that process is terminated/exit.
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 5 AND user.name: SYSTEM AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*)
```
## Potential Local Privilege Escalation - Applocker Events by SYSTEM in User-Writable Paths
#### Depending on your Applocker configuration - Could be used to catch events related to DLL/EXE etc...alternative if you dont have SYSMON set but will likely miss alots of DLL events. Applocker could also be good for catching DLL/EXE events in Program Files which SYSMON will likely miss.
```
event.provider: "Microsoft-Windows-AppLocker" AND event.code: [8000 TO 8005] AND (user.name: SYSTEM OR *\$) AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*)
```
