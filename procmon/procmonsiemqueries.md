# Procmon SIEM Queries
**Queries to use after ingesting the Procmons ndjson files (converted from CSV) in to a SIEM solution with relevant columns mentioned in the `README` section.**

>**Pro Tip: If a high-privileged process accesses something that a low-privileged user can modify, it may be exploitable.**
>

## Potential Local Privilege Escalation - Generic Wide Query
#### Use wildcards if needed 
```
User: SYSTEM AND Path: (ProgramData OR Users OR Temp OR Tmp)
```
##### 
