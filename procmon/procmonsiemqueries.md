# Procmon SIEM Queries
**Queries to use after ingesting the Procmons ndjson files (converted from CSV) in to a SIEM solution with relevant columns mentioned in the `README` section.**
The queries with ⭐ mark is extra highly relevant.

>**Pro Tip: If a high-privileged process accesses something that a low-privileged user can modify, it may be exploitable.**
>

## Potential Local Privilege Escalation - Generic Wide Query
#### Use wildcards if needed 
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp)
```

## Potential Local Privilege Escalation - NOT FOUND Events ⭐
#### Look for file extensions like `.dll`, `.exe`, `.sys`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` or config files like XML, json etc.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: ("NAME NOT FOUND" OR "PATH NOT FOUND")
```

## Potential Local Privilege Escalation - NO SUCH FILE Events 
#### Look for file extensions like `.dll`, `.exe`, `.sys`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` or config files like XML, json etc.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: ("NO SUCH FILE")
```


## Potential Local Privilege Escalation - ACCESS DENIED Events
#### Reveals where privileged processes are trying to access protected resources. Those access attempts can sometimes be manipulated or redirected, leading to local privilege escalation (LPE).
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: "ACCESS DENIED"
```

## Potential Local Privilege Escalation - NAME INVALID Events
#### The Result: "NAME INVALID" in Procmon happens when a process attempts to access a resource whose name the OS considers invalid. NAME INVALID usually indicates a naming or path problem with illegal characters.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: "NAME INVALID"
```

## Potential Local Privilege Escalation - Generic query for Config files 
#### User-controlled configuration used by privileged process which may be used to execute exe/scripts etc. Look for existing/missing files, existing , ReadFile operations etc.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Path: (*.ini OR *.config OR *.cfg OR *.xml OR *.json)
```
>**In config adding variables or values like script=, command=, Example: script=C:\temp\privesc.ps1**
>
- Ref: https://github.com/serilog/serilog-settings-configuration/blob/dev/sample/Sample/appsettings.json 
**Look for keys/variables Like path, Template, outputTemplate** `Missed the chance of CVE-2025-1789`



## Potential Local Privilege Escalation - Generic query for 32 bit executables spawning processes like cmd, schtasks etc.
#### SysWOW64 → Folder containing 32-bit system files on a 64-bit Windows system which is odd behaviour if cmd.exe, powershell.exe, pwsh.exe. Common that 3rd party applicaion 32 bits executables has vulnerabilities, gives you an idea of executables to look more into.
```
User: SYSTEM AND Image Path: "C:\Windows\SysWOW64\cmd.exe"
```


## Potential Local Privilege Escalation - Generic query for Command Line
#### Look for cmd.exe, powershell.exe, pwsh.exe or other script engies executing scripts from User-writable paths.
```
User: SYSTEM AND Command Line: (ProgramData OR Users OR Temp OR Tmp) AND Command Line: (*.dll* OR *.exe* OR *.sys* OR *ps1* OR *.bat* OR *.cmd* OR *.js* OR *.vbs*) 
```

## Potential Local Privilege Escalation - SetSecurityFile Events
#### `SetSecurityFile` occurs when a process attempts to **change the security descriptor (ACL)** of a file or folder. Correlate SetSecurityFile events with ACL inspection to identify LPE opportunities.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Operation: SetSecurityFile
```
## Potential Local Privilege Escalation - Generic CreateFile Events for files with file extension.
#### `CreateFile` Is that a File handle is created and you have to look in to result/detail to get more context about whats happening.ccurs when a process attempts to 
```
User: SYSTEM AND Operation: CreateFile AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: SUCCESS AND Path: *.* AND NOT Path: (Microsoft)
```

## Potential Local Privilege Escalation - FileWrite Of .LOG files Events
#### SUCCESS OF `Create File **. Check ACL, if you can delete, and if you can symlink and get LPE. Check Referens with Troopers19 File Operators pdf.
```
User: SYSTEM AND Operation: CreateFile AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: SUCCESS AND Path: *.log AND NOT Path: (Microsoft)
```
#### NOT FOUND OF `Create File **. Check ACL, if you can delete, and if you can symlink and get LPE. Check Referens with Troopers19 File Operators pdf.
```
User: SYSTEM AND Operation: CreateFile AND Path: (ProgramData OR Users OR Temp OR Tmp) AND NOT Result: SUCCESS AND Path: *.log AND NOT Path: (Microsoft)
```

## Potential Local Privilege Escalation - WriteFile Of interesting file extensions.
```
User: SYSTEM AND Operation: WriteFile AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Path: (*.dll OR *.exe OR *.sys OR *.ps1 OR *.bat OR *.cmd OR *.js OR *.vbs OR *.ini OR *.config OR *.cfg OR *.xml OR *.json) AND NOT Path: (Microsoft)
```
## Potential Local Privilege Escalation - FileDelete Events
#### `SetDispositionInformationFile` Delete with True occurs when a file deletion happes**. Check ACL and if you can symlink and get LPE. We want to delete a file using a high privileged process so we can create it afterwards our self. Check Referens with Troopers19 File Operators pdf.We 
```
(User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Operation: SetDispositionInformationFile AND Detail: "Delete: True") OR (User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Operation: CreateFile AND Detail: "Desired Access: Delete")
```
> **May also be interesting to query and look for Flags: FILE_DISPOSITION_DELETE in the Details column with SetDispositionInformationFile Operation.**

## Potential Local Privilege Escalation - FileRename Events
```
(User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Operation: (Rename OR SetRenameInformationFile OR SetInformationFile))
```
> **CVE-2020-0668 - A Trivial Privilege Escalation Bug in Windows Service Tracing** https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/


## Potential Local Privilege Escalation - NAME NOT FOUND / PATH NOT FOUND / NO SUCH FILE Events in C-Root
#### Look for file extensions like `.dll`, `.exe`, `.sys`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` or config files like XML, json etc.
> Files that can give you code execution is relevant.
```
User: SYSTEM AND Result: ("NAME NOT FOUND" OR "PATH NOT FOUND" OR "NO SUCH FILE") AND NOT Path: (ProgramData OR Users OR Temp OR "Program Files" OR Windows) AND NOT Operation: Reg*
```


## Potential Local Privilege Escalation - OpenSSL config (openssl.cnf) file
#### Look for the ones that you can modify or write.
> Check Offensive SIEM documentation for how to privilege escalate. NOT FOUND events are highly relevant but also SUCCESS on Paths that you can modify.
```
User: SYSTEM AND Path: openssl.cnf
```
- ref https://blog.mirch.io/2019/06/10/cve-2019-12572-pia-windows-privilege-escalation-malicious-openssl-engine/

  ## Potential Local Privilege Escalation - serilog config file
  #### Check the ACL if you can modify the configuration file.
  ##### If you can modify, you can add  "outputTemplate" to add custom data to the log, you can also specify file name. Which basicly gives you file overwrite with what the file will contain. A privilege escalation could be overwriting a script in a protected path that runs with higher privileges and add commands to it.
  ```
  User: SYSTEM AND Path: *serilogSettings.json AND Path: (ProgramData OR Users OR Temp)
  ```
**General about Serilog** - https://esmp.dev/configuring-serilog-through-appsettings-json-file-33b26594bb46
- Missed CVE-2025-1789

## Potential Local Privilege Escalation - appsettings.json config file that could be for serilog.
#### Start with first query to find applications with appsettings.json in User-writable path.
```
User: SYSTEM AND Path: *appsettings.json AND Path: (ProgramData OR Users OR Temp)
```
#### Second will be to cross reference if that application has serilog library (dll) files.
```
Path: *serilog* AND Path: *.dll
```
**If you find same application with DLL files, try to customize the appsettings.json**

*start with altering the file path.. can you modify the file name and file path?*

*then go with template and try do add own data/text*
