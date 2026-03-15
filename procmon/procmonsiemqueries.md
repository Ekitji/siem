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

## Potential Local Privilege Escalation - Generic query for Config files 
#### User-controlled configuration used by privileged process which may be used to execute exe/scripts etc. Look for existing/missing files, existing , ReadFile operations etc.
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp) AND Path: (*.ini OR *.config OR *.xml *.json)
```
>script=

plugin=

command=

update_url=

**Example: script=C:\temp\privesc.ps1**
>


