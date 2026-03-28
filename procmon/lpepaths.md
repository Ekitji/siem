# Arbitrary File Write
- Overwrite a file
- Drop a file where it can be used for DLL Hijacking
- We must be able to control the content or
- the file write shall mess the ACL and give over permissive ACL.
- if we can only control the filename then its maybe a Denial Of Service by overwriting system files.
> Common with log files

# Arbitrary File Delete
- Remove files that we can replace in
* C:\ProgramData
* C:\Windows\Temp
* C:\Root\subfolders (that is not Program Files)
> Default rights allow low privileged users to create files and directories but not to modify existing ones.

# Serilog.json/appsettings.json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "Installation": {
    "AgentType": "computer",
    "ApplicationDataPath": "C:\\ProgramData\\CustomApp"
  },
  "Serilog": {
    "Using": [ "Serilog.Sinks.File" ],
    "MinimumLevel": {
      "Default": "Warning"
    },
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "C:\\Program Files\\Highprivileged\\script\\startup.ps1",
          "rollingInterval": "Day",
          "shared": true,
          "outputTemplate": "{whoami >> C:\temp\test.txt#}"
        }
      }
    ]
  }
}





## Arbitrary file overwrite / privileged file write. 
If a privileged service writes to a pathname that can resolve to a hard-linked target, the write may land in a more sensitive file than intended. The Almond write-up explicitly treats privileged create/copy/move/write behavior on user-influenced files as a route to local privilege escalation.

## Arbitrary file delete. 
If the privileged service later deletes or replaces that pathname, it can end up deleting the linked target instead. That is why hard links often show up around delete workflows, temp-file cleanup, or replace-in-place logic.

## Privilege escalation. 
If the resulting write/delete reaches a file that a privileged process will later load, execute, or trust, the bug can become an EoP issue rather than just a local integrity issue. The Almond article calls out DLL hijacking and overwrite of executable/script/config targets as common end states for arbitrary file write bugs.

## Denial of service
Even when you cannot turn it into code execution, steering a privileged delete or overwrite into important application files can still break the service or product. The same article notes arbitrary file delete as a practical DoS vector even when escalation is not available

## DACL for SetSecurityFile

- **Information: DACL**  
  Only the **DACL** was being changed. That is the normal “permissions changed” case, because the DACL controls who is allowed or denied access.

- **Information: Owner, DACL, DACL Protected**  
  The **owner** changed, the **DACL** changed, and the DACL was marked **protected**, meaning it will not inherit ACEs from the parent.

- **Information: Owner, Group, DACL, DACL Protected**  
  The **owner** changed, the **primary group** changed, the **DACL** changed, and inheritance on the DACL was blocked.

- **Information: Owner, Group, DACL**  
  The **owner**, **primary group**, and **DACL** changed, but there is no explicit protected/unprotected inheritance flag shown in that entry.

- **Information: Owner, DACL, DACL Unprotected**  
  The **owner** changed, the **DACL** changed, and the DACL was marked **unprotected**, meaning it inherits ACEs from the parent object.

- **Information: Owner, DACL, SACL, DACL Protected, SACL Unprotected**  
  The **owner** changed, the **DACL** changed, the **SACL** changed, the DACL was marked **protected** so it does not inherit, and the SACL was marked **unprotected** so it does inherit from the parent. The SACL is the audit/system ACL, not the normal allow/deny permission list.

### Quick decoder

- **Owner** = object ownership changed.
- **Group** = primary group changed.
- **DACL** = normal access permissions changed.
- **SACL** = audit/system ACL changed.
- **DACL Protected** = stop inheriting ACEs into the DACL.
- **DACL Unprotected** = allow the DACL to inherit ACEs from parent.
- **SACL Unprotected** = allow the SACL to inherit ACEs from parent.
