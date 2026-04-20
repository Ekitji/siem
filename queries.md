
# Services

## Potential Local Privilege Escalation - Service Created in User-Writable Path
#### Event.code 7045 query catches also none SYSTEM services - Specify using winlog.event_data.AccountName: LocalSystem if that field is indexed.
```
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4697 AND winlog.logon.id: 0x3e7 AND winlog.event_data.ServiceFileName: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*)) OR (event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ImagePath: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*))
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
## Potential Local Privilege Escalation - Service Binary missing - The system cannot find the file specified.
#### You need to identify what user the service is running as and the binary path. Maybe we can plant our own binary?
```
event.provider: "Service Control Manager" AND event.code: 7000 AND winlog.event_data.param2: "%%2"
```
> The SCM tried to start a service, went to the ImagePath in the registry (HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath), and the binary wasn't there.


# Schedule Tasks

## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as SYSTEM
#### User-Writable Paths in the Arguments (SYSTEM User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Users\\* OR *C\:\\Windows\\Temp*) AND message: *HighestAvailable*)
```
#### User-Writable Paths in the Binary path (SYSTEM User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*) AND message: *HighestAvailable*)
```

#### User-Writable Paths in the Arguments (SYSTEM User covering UserID and GroupID for System user) - Cover your language locale for SYSTEM user - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698) AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Users\\* OR *C\:\\Windows\\Temp*) AND message: (*HighestAvailable* OR *System* OR *S\-1\-5\-18* OR *NT\ AUTHORITY\\SYSTEM* OR *NT\ instans\\SYSTEM*))
```

#### User-Writable Paths in the Binary path (SYSTEM User covering UserID and GroupID for System user) - Cover your language locale for SYSTEM user - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698) AND winlog.event_data.Command: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*) AND message: (*HighestAvailable* OR *System* OR *S\-1\-5\-18* OR *NT\ AUTHORITY\\SYSTEM* OR *NT\ instans\\SYSTEM*))
```

#### C-Root Paths in the Arguments (SYSTEM User) -  may also be interesting to query fo D:\, E:\, Network shares etc. - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\*) AND NOT winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Program\ Files* OR C\:\\Users\\* OR C\:\\Windows\\*) AND message: *HighestAvailable*)
```

#### C-Root Paths in the Arguments (SYSTEM User covering UserID and GroupID for System user)-  may also be interesting to query fo D:\, E:\, Network shares etc. - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\*) AND NOT winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Program\ Files* OR *C\:\\Users\\* OR C\:\\Windows\\*) AND message: (*HighestAvailable* OR *System* OR *S\-1\-5\-18* OR *NT\ AUTHORITY\\SYSTEM* OR *NT\ instans\\SYSTEM*))
```

#### C-Root Paths in the Binary (SYSTEM User covering UserID and GroupID for System user)-  may also be interesting to query fo D:\, E:\, Network shares etc. - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (*C\:\\*) AND NOT winlog.event_data.Command: (*C\:\\ProgramData\\* OR *C\:\\Program\ Files* OR C\:\\Users\\* OR C\:\\Windows\\*) AND message: (*HighestAvailable* OR *System* OR *S\-1\-5\-18* OR *NT\ AUTHORITY\\SYSTEM* OR *NT\ instans\\SYSTEM*))
```


## Potential Local Privilege Escalation - Scheduled Task from User-Writable Path Created as Administrator
##### "Highest available" only elevates if the task’s run-as account is an Administrator. If the run-as account is a standard user, there’s no higher integrity to elevate to, so the task runs at the user’s normal Medium integrity—regardless of the “Run with highest privileges” checkbox
#### User-Writable Paths in the Arguments (Administrator User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND NOT winlog.logon.id: "0x3e7") AND winlog.event_data.Arguments: (*C\:\\ProgramData\\* OR *C\:\\Users\\* OR *C\:\\Windows\\Temp*) AND message: *HighestAvailable*)
```
#### User-Writable Paths in the Binary path (Administrator User) - check winlog.event_data.TaskContent for more context
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND NOT winlog.logon.id: "0x3e7") AND winlog.event_data.Command: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*) AND message: *HighestAvailable*)
```
#### C-Root Paths in the Arguments (Administrator User) -  may also be interesting to query for D:\, E:\, Network shares etc. - check winlog.event_data.TaskContent for more context
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
##### This query will show you scheduled tasks that has for an example powershell as the binary, and the command is "Start-Process -WindowsStyle Hidden task.bat" Where task.bat is a batch file and the location of it is set in the schedule task by using "Start in" to set the "WorkingDirectory"
#### Generic query to only catch when Working Directory is set to a User-Writable path. Check winlog.event_data.TaskContent for more context and if its a privilege escalation path.
```
((event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4698 AND message: *WorkingDirectory*) AND message: (*ProgramData* OR *C\:\\Users\\* OR *Temp*))
```

## Potential Local Privilege Escalation - Scheduled Task Binary missing / The system cannot find the file specified.
#### You need to identify what user the Schedule task is running as and the binary path. Maybe we can plant our own binary?
```
event.provider: "Microsoft-Windows-TaskScheduler" AND event.code: 101 AND winlog.event_data.ResultCode: (2147942402 OR 2147942667)
```
> The Task Scheduler tried to launch the binary or script defined in that task and it didn't exist at the path specified. The ResultCode is Microsoft Error Codes.

## Potential Local Privilege Escalation - Scheduled Task SDDL (ACL) Enumeration
#### Look in the message field for <SecurityDescriptor> key and convert to human readable and check the permissions for the schedule task. 
##### Query to hunt for misconfigured Schedule tasks that regular user can change/modify. Microsoft related ones are whitelisted simply because they are protected paths. We are interested in the ones that runs with higher privileges like System or Administrator (or HighestAvailable). Can be good to normalize and parse out the SecurityDescriptor as a field and work from there by whitelisting the correct ones.
```
event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: (4700 OR  4701 OR 4698) AND message: *SecurityDescriptor* AND NOT winlog.event_data.TaskName: (\\Microsoft\\Windows\\* OR \\Microsoft\\Office\\*) 
```
> **Pro Tip:** To generate more events run a script that disables and re-enables all tasks on a endpoint/workstation that you have logs from. Re-enabling will trigger and log schedule task enabled and you will catch the SecurityDescriptor there for Tasks that you did not have any SecurityDescriptor from ex. some of the event.code 4698.

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

# PATH
## PATH entries and writable directories in the system PATH
##### Look for PATHS pointing to User-Writable ones like C:\ProgramData\* OR C\:Users\* OR TEMP
##### If a PATH entry is world-writable (meaning any local user can alter it), then an attacker can place malicious executables or DLLs there. Because Windows searches PATH entries in order, this allows search order hijacking — where the attacker’s code runs instead of the legitimate program
#### Detection with process creation events for SYSTEM-level environment variable targeting SYSTEM context and /M machine-level changes
```
((event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND user.name: SYSTEM AND process.name: setx.exe) OR 
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND process.name: setx.exe AND process.args: \/M) OR 
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4688 AND winlog.event_data.SubjectUserSid: "S-1-5-18" AND process.name: setx.exe) OR 
(event.provider: "Microsoft-Windows-Security-Auditing" AND event.code: 4688 AND process.name: setx.exe AND process.args: \/M))
```

## System (machine-level) PATH environment variable in the registry
##### Look for PATHS pointing to User-Writable ones like C:\ProgramData\* OR C\:Users\* OR TEMP in winlog.event_data.Details field.
#### HKU\S-1-5-18\Environment may also be interesting to look at, can also be useful to look at Sysmons event.code 14
```
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: (12 OR 13) AND registry.hive: HKLM AND registry.path: HKLM\\System\\CurrentControlSet\\Control\\Session\ Manager\\Environment\\Path) OR
(event.provider: "Microsoft-Windows-Sysmon" AND event.code: (12 OR 13) AND registry.path: HKU\\S-1-5-21\\Environment\\*)
```

# Centralized Application Deployment

## Potential Local Privilege Escalation - Process Creation by SYSTEM in User-Writable Paths ⭐
#### Catches also none Centralized application deployments, its more a generic query that also catches schtasks or services as parent process. Do a separate query for C:\Windows\Temp
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
#### Dont forget to look for creation of script files also in C-root subfolder.
```
(event.provider: Microsoft-Windows-Sysmon
AND event.code: 11 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\* ) AND file.extension: (cmd OR bat OR ps1 OR vbs))
```

## Potential Local Privilege Escalation - BAT Files Executed from ProgramData ⭐
#### Dont forget to create the query for powershell + ps1 and other script engines/files, will likely also catch schtask scripts. Query also for Temp folder and other User-writable paths.
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe ) OR
(event.code: 4688 AND winlog.event_data.TokenElevationType: "%%1936" AND process.command_line: *ProgramData* AND process.command_line: /.*[Bb][Aa][Tt].*/ AND process.name: cmd.exe)
```

## Potential Local Privilege Escalation - Startup scripts as SYSTEM used
##### Startup/Shutdown scripts - Check the process command line field. Look for User-writable paths in binary path or command line, networks shares that are in User-writable location, read the script file from the SYSVOL network share and look for sensitive information like passwords misconfigurations etc.
#### Generic query - If needed add ProgramData, Users, C-root etc to the query to narrow it down. 
```
((event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-16384" AND process.parent.name: gpscript.exe) OR (event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: System AND process.parent.name: gpscript.exe))
```

## Potential Local Privilege Escalation - Logon scripts as Administrator used
##### Logon/Logoff scripts - Check the process command line field. Look for user-writable paths in the binary path or command line, network shares in user-writable locations, and non-existent or broken share paths. Review permissions on the referenced share, file, NETLOGON/SYSVOL location, logon script, and any GPO-linked logon script to identify unsafe access controls. Determine whether privileged or administrator accounts are assigned logon scripts, including cases where those scripts are mapped from non-existent shares. Read the script file itself and look for plaintext credentials, passwords, other embedded sensitive information, and general script misconfigurations.


#### Generic query - If needed add ProgramData, Users, C-root etc to the query to narrow it down. Could also be interesting to query for none-admin executed scripts. It could be that no admin has still not logged in where that GPO is set and it could be a vulnerability when high privileged user logs in.
```
((event.provider: Microsoft-Windows-Security-Auditing AND event.code: 4688 AND winlog.event_data.MandatoryLabel: "S-1-16-12288" AND process.parent.name: gpscript.exe) OR (event.provider: "Microsoft-Windows-Sysmon" AND event.code: 1 AND winlog.event_data.IntegrityLevel: High AND process.parent.name: gpscript.exe))
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
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 7 AND user.name: SYSTEM AND NOT file.path: (C\:\\Program\ Files* OR C\:\\Windows\\* OR C\:\\Users\\* OR C\:\\ProgramData\\*)
```

# Arbitrary File delete
## Potential Arbitrary File delete by SYSTEM in User writable paths
##### May also be interesting to look inte other file operators
```
(event.provider: Microsoft-Windows-Sysmon AND user.name: SYSTEM AND event.code: (23 OR 26) AND file.path: (C\:\\Users\\* OR C\:\\ProgramData\\* OR C\:\\Windows\\Temp\\*))
```
> **Pro tip** For detection using SIEM. Install every application that you are allowed to, then spray Users and Programdata folders and subfolders with a file name you know will be logged if deleted. For an example test.exe sprayed into every folder and subfolder on a workstation. Then do your query to see if you catch something. It could be that a delete operation exists but a file never is put there per default.

## Potential Arbitrary File delete by SYSTEM in C-Root subfolder
##### May also be interesting to look inte other file operators
```
(event.provider: Microsoft-Windows-Sysmon AND user.name: SYSTEM AND event.code: (23 OR 26) AND file.path: (C\:\\*) AND NOT file.path: (C\:\\Users\\* OR C\:\\ProgramData\\* OR C\:\\Program\ Files* OR C\:\\Windows\\*)
```
> **Pro tip** Check above pro-tip for better detection opportunities by spraying own files and generating events by that.
# Kernel Drivers Loaded

## Potential Local Privilege Escalation - Kernel Drivers Loaded from User-Writable Paths
##### Look for none randomized names, we are more interested in static names. Dont forget to look for C-root subfolder also. For more context look at file.code_signature.subject_name field which shows the signer.
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 6 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*))
```

## Potential Local Privilege Escalation - Sys-Files Created by SYSTEM in User-Writable Paths
##### Look for none randomized names, we are more interested in static names. Dont forget to look for C-root subfolder also
```
(event.provider: Microsoft-Windows-Sysmon AND event.code: 11 AND user.name: SYSTEM AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\*) AND file.extension: (sys OR SYS))
```

## Potential Local Privilege Escalation - Service created with Kernel driver in User-writable path
##### Look for sys files and if found check ACL for the file path.
```
(event.provider: "Service Control Manager" AND event.code: 7045 AND winlog.event_data.ServiceType: (*kernel* OR *file\ system* OR *\ 1 OR *\ 2) AND winlog.event_data.ImagePath: (C\:\\ProgramData\\* OR C\:\\Users\\* OR C\:\\Windows\\Temp\\) AND NOT winlog.event_data.ImagePath: C\:\\ProgramData\\Microsoft\\Windows\ Defender\\*)
```

# Other Queries - Some for Layer on Layer coverage
## Potential Local Privilege Escalation - Possible OpenSSL Config (openssl.cnf) Usage with Legacy drivers ⭐
#### Query that searches for legacy OpenSSL driver libeay32.dll that has almost in every case hardcoded user-writable path to c:\usr\local\ssl. Start with this query and go with the next one for a wider search where you will also catch newer OpenSSL versions that you later need to lookup its OPENSSLDIR.
```
event.provider:"Microsoft-Windows-Sysmon" AND event.code: 7 AND file.extension:"dll" file.pe.description: "OpenSSL library" file.pe.file_version: (0.9.* OR 1.0.*) AND file.pe.original_file_name: (libeay32.dll) AND user.name: SYSTEM 
```
> **Pro Tip** Check if the process executable is started from services.exe or as a schedule task. If so - you have a nice persistent local privilege escalation vulnerability.

> We have to manually verify the process if its calling OPENSSL_config or CONF_modules_load_file then we have a privilege escalation or if  OPENSSL_no_config is not set. 

## Potential Local Privilege Escalation - Possible OpenSSL Config (openssl.cnf) Usage ⭐
#### Look at the fields process executable, file path to the dll, file.pe.file_version, sha1 hash field. **Prioritize filenames libeay32.dll and libcrypto-1_1*.dll** which is older/legacy DLLs and are more likely vulnerable, but dont skip the other ones. You can use https://github.com/Ekitji/siem/blob/main/openssl/OpenSSL_Binaries.md which is a pre-built table with lots of hashes of openssl dlls with hardcoded OPENSSLDIR. If you cant find your DLL on that list, ask for a copy of the DLL you found or simply install the application and do the controls your self. Event.code 7 is for image loaded and will give you the possible vulnerable process loading the DLL. File creation/deletion events will likely give you the installer executables and are mot for finding the existence of the file.
```
event.provider:"Microsoft-Windows-Sysmon" AND event.code: 7 AND file.extension:"dll" AND (file.name:libcrypto*.dll OR file.name:libssl*.dll OR file.name:libeay*.dll OR file.name:ssleay*.dll OR file.name:openssl.dll OR file.pe.original_file_name:libcrypto*.dll OR file.pe.original_file_name:libssl*.dll OR file.pe.original_file_name:libeay*.dll OR file.pe.original_file_name:ssleay*.dll) AND user.name: SYSTEM
```
> **Pro Tip** if OPENSSLDIR is set to /usr/local/ssl, in windows this is translated to c:\usr\local\ssl and is a user-writable path. Check the process executable that its a high privileged process that are started by a service or schedule task. If so then you probably have your persistent local privilege escalation.

> We have to manually verify the process if its calling OPENSSL_config or CONF_modules_load_file then we have a privilege escalation or if  OPENSSL_no_config is not set.

> **OpenSSLDir Tools** - https://github.com/Ekitji/siem/tree/main/openssl

> **Event.code: 7** can be excluded to catch file creation/deletion events but is less relevant then the actual image load of the OpenSSL related DLLs.



## Potential Local Privilege Escalation - Possible NSIS installer bugs ⭐
####  NSIS (Nullsoft Scriptable Install System) installer script uses a plugin (such as nsExec.dll) which reveals that the Installer base is NSIS related. Some of the nsExec.dll has PE metadata showing version in field file.pe.file_version. nsExec.dll files in C:\Windows\Temp\*.tmp\nsExec.dll path is highly relevant to research more. The nsExec.dll is fairly common in NSIS usage.
```
event.provider:"Microsoft-Windows-Sysmon" AND user.name: SYSTEM AND event.code: 7 AND file.name: nsExec.dll
```
**You could also use file creation events (event code 11) to find the NSIS related installers/uninstallers**
> NSIS before 3.09 mishandles access control for an uninstaller directory.

> NSIS before 3.11 contains a race condition in the temporary plugin directory creation logic, caused by incomplete checking of the CreateRestrictedDirectory return value.

**If you find older npcap installer/uninstaller dont miss the binary planting of net.exe, certutil.exe, pnputil.exe, and netsh.exe**

> **Ref.** https://blog.amberwolf.com/blog/2026/april/next-next-system/


## Potential Local Privilege Escalation - Possible NSIS installer bugs - Wide query
####  NSIS (Nullsoft Scriptable Install System) installer script uses a plugin using DLLs. The query holds common DLL file names used with NSIS with a common file path to C:\Windows\Temp
```
event.provider:"Microsoft-Windows-Sysmon" AND user.name: SYSTEM AND event.code: 7 AND file.name: (System.dll OR nsDialogs.dll OR nsExec.dll OR StartMenu.dll OR LangDLL.dll OR Banner.dll OR InstallOptions.dll OR UserInfo.dll OR Dialer.dll OR Math.dll OR NSISdl.dll OR Splash.dll OR AdvSplash.dll OR BgImage.dll OR inetc.dll OR InetLoad.dll OR UAC.dll OR AccessControl.dll OR Registry.dll OR ShellLink.dll OR SimpleFC.dll OR FindProcDLL.dll OR KillProcDLL.dll OR NScurl.dll OR ZipDLL.dll OR unzipdll.dll OR untgz.dll OR VPatch.dll OR CabDLL.dll OR nsJSON.dll OR StdUtils.dll OR ExecDos.dll) AND file.path: C\:\\Windows\\Temp\\*
```
> **file.pe.description**: NSIS: Nullsoft Scriptable Install - field shows if its Nullsoft related and **file.pe.file_version** shows potential NSIS version if the metadata exists. **file.pe.description** could also hold NSIS related word.


## Potential Local Privilege Escalation - Possible dotLocal redirection vulnerability
####  Query catches DLL loads from WinSxS which could point you to right direction to find applications vulnerable to dotLocal (.local) redirection DLL vulnerabilities. This vulnerability seems to be fixed in later Windows 11 builds.
#### comctl32.dll is one of the relevant DLLs. What you need to do is to manually check with procmon if it the process tries to load from same directory dll in processname.local directory. Look for NAME NOT FOUND events.
```
event.provider:"Microsoft-Windows-Sysmon" AND user.name: SYSTEM AND event.code: 7 AND file.path: (C\:\\Windows\\WinSxS\\amd64* OR C\:\\Windows\\WinSxS\\x86*) AND file.extension: dll AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\ OR C\:\\Windows\\Temp\*)
```
> **Ref** https://www.advancedinstaller.com/exe-local-directory-vulnerability-solution.html

> **NAME NOT FOUND** https://cdn.advancedinstaller.com/img/exe-local-directory-vulnerability-solution/gdiplus-dll-hijacking-risk.png 




## Potential Local Privilege Escalation - Possible dotLocal vulnerable WiZ installer
#### You need to determine if the application is vulnerable or not. file.pe.file_version should give you context to find the affected versions. Affected versions >= 4, < 4.0.4 < 3.14.0
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 7 AND file.pe.company: "WiX Toolset" AND process.executable: C\:\\Users\\*\\AppData\\Local\\Temp\\*\\.be\\*
```
> **Ref** - https://github.com/wixtoolset/issues/security/advisories/GHSA-7wh2-wxc7-9ph5
##### You could also query for process creation event, 4688 or 1, executable with .be in the path.
```
event.provider: Microsoft-Windows-Sysmon AND event.code: 1 AND process.executable: C\:\\Users\\*\\AppData\\Local\\Temp\\*\\.be\\*
```




## Potential Local Privilege Escalation - Process Terminated by SYSTEM in User-Writable Paths
##### Will also give you an idea for the process creation query when that process is terminated/exit.
```
event.provider: "Microsoft-Windows-Sysmon" AND event.code: 5 AND user.name: SYSTEM AND process.executable: (C\:\\ProgramData\\* OR C\:\\Users\\*)
```

## Potential Local Privilege Escalation - Group Policy Preferences Errors enumeration
##### Event 4117 in Microsoft Windows appears in the GroupPolicy/Operational log and indicates that a Group Policy Preference (GPP) item failed to apply. While it’s primarily an administration/troubleshooting event, it can sometimes reveal privilege-escalation opportunities when the failure involves misconfigured paths, permissions, scheduled tasks, missing binaries/scripts. 
```
event.provider:"Microsoft-Windows-GroupPolicy" AND event.code:4117
```



## Potential Local Privilege Escalation - Applocker Events by SYSTEM in User-Writable Paths
##### Depending on your Applocker configuration - Could be used to catch events related to DLL/EXE etc...alternative if you dont have SYSMON set but will likely miss alots of DLL events. Applocker could also be good for catching DLL/EXE events in Program Files which SYSMON will likely miss.
```
event.provider: "Microsoft-Windows-AppLocker" AND event.code: [8000 TO 8005] AND (user.name: SYSTEM OR *\$) AND file.path: (C\:\\ProgramData\\* OR C\:\\Users\\*)
```

## MSHTA running .hta files from User-Writable Paths
#### Checks when SYSTEM or Administrator is executing mshta which points to a .hta file in User-Writable Paths. 
```
(event.provider: "Microsoft-Windows-Security-Auditing" AND process.name: mshta.exe AND winlog.event_data.TokenElevationType: (%%1936 OR
%%1937) AND process.command_line: (*ProgramData* OR *Users* OR *Temp* OR *Tmp*)) OR (event.provider: "Microsoft-Windows-Sysmon" AND process.name: mshta.exe AND winlog.event_data.IntegrityLevel: (High OR System) AND process.command_line.text: (*ProgramData* OR *Users* OR *Temp* OR *Tmp*))
```
