
# Services

## Potential Local Privilege Escalation - Service Executables in User-Writable Paths
```
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*)) OR (event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.parent.name: services.exe AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
```

## Potential Local Privilege Escalation - Service Created in User-Writable Path
```
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.logon.id: 0x3e7 AND winlog.event_data.ServiceFileName: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*)) OR (event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\Windows\\Temp\\*))
```

## Potential Local Privilege Escalation - Unquoted Service Path
```
((event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath:*\ * AND NOT winlog.event_data.ImagePath:\"* ) OR (event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.event_data.ServiceFileName:*\ * AND NOT winlog.event_data.ServiceFileName:\"*)) AND NOT winlog.event_data.ServiceFileName: (C\:\\WINDOWS\\system32\\* OR C\:\\WINDOWS\\System32\\* OR C\:\\Windows\\system32\\* OR C\:\\Windows\\System32\\* OR C\:\\windows\\system32\\* OR \%SystemRoot\%\\System32\\* OR 
C\:\\windows\\System32\\*) AND NOT winlog.event_data.ImagePath: (C\:\\WINDOWS\\system32\\* OR \%SystemRoot\%\\System32\\* OR C\:\\windows\\system32\\*)
```

# Schedule Tasks

## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as SYSTEM
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp) AND message: *HighestAvailable*)
```

# DLL Sideloading

## Potential Local Privilege Escalation - Printer DLL Load from User-Writable Paths
```
((event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND process.name: (PrintIsolationHost.exe OR spoolsv.exe)) AND NOT file.path: (C\:\\Windows\\System32\\* OR  C\:\\Program\ Files*))
```

## Potential Local Privilege Escalation - Generic DLL Load from User-Writable Paths
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*) AND file.extension: (dll OR DLL))
```

## Potential Local Privilege Escalation - DLL Load from Temp Directory
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 7 AND user.name: SYSTEM AND file.path: (C\:\\Windows\\Temp\\*) AND file.extension: (dll OR DLL))
```

# Centralized Application Deployment

## Potential Local Privilege Escalation - Process Creation by SYSTEM in User-Writable Paths
```
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
OR
(event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*))
```

## Potential Local Privilege Escalation - Uninstall Process Creation
```
process.name: unins*
```

# Scripts

## Potential Local Privilege Escalation - Script Files Created by SYSTEM in User-Writable Paths
```
(event.provider: Microsoft-Windows-Sysmon
AND event.code: 11 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*) AND file.extension: (cmd OR bat OR ps1 OR vbs))
```

## Potential Local Privilege Escalation - BAT Files Executed from ProgramData
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe)
(event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe)
```

# C-Root Folder

## Potential local Privilege escalation vulnerability found - Process Creation by SYSTEM in C-Root subfolder
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
