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
##### 

## Potential Local Privilege Escalation - NOT FOUND Events ⭐
#### Look for file extensions like `.dll`, `.exe`, `.sys`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs` or config files like XML, json etc.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Result: ("NAME NOT FOUND" OR "PATH NOT FOUND")
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
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Path: (*.ini OR *.config OR *.xml *.json)
```
>**In config adding variables or values like script=, command=, Example: script=C:\temp\privesc.ps1**
>
- Ref: https://github.com/serilog/serilog-settings-configuration/blob/dev/sample/Sample/appsettings.json 
**Look for keys/variables Like path, Template, outputTemplate** `Missed the chance of CVE-2025-1789`

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
