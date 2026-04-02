# AD 5136 Queries for Elastic

This document contains **Elastic KQL queries** for hunting risky Active Directory changes with **Event ID 5136**, plus investigation notes for each query.

---

## How to use these queries

Most queries focus on:

- `event.code:"5136"`
- `host.os.type:"windows"`
- `winlog.event_data.OperationType:"%%14674"`

That operation type represents **Value Added**, which is usually the most useful 5136 view when looking for newly introduced misconfigurations.

---

## 1) Base hunt

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674"
```

### What this finds
All audited AD object changes where a value was added.

### What to look for if this returns results
Review:

- `SubjectUserName` — who made the change
- `ObjectDN` — what object changed
- `ObjectClass` — user, computer, group, GPO, etc.
- `AttributeLDAPDisplayName` — what attribute changed
- `AttributeValue` — the new value

### Investigate further when
- a helpdesk or service account modifies privileged objects
- the actor normally should not edit AD objects
- the object is privileged or sensitive
- the change happened outside normal change windows

---

## 2) Resource-Based Constrained Delegation (RBCD)

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:"msDS-AllowedToActOnBehalfOfOtherIdentity"
```

### What this finds
Changes to the attribute used for **resource-based constrained delegation**.

### What to look for if this returns results
Review:

- the target computer in `ObjectDN`
- the modifying account in `SubjectUserName`
- the new value in `AttributeValue`
- whether the target server was expected to receive delegation changes

### Investigate further when
- the change was not part of an approved delegation rollout
- the actor is not a known AD / server admin
- the affected computer is sensitive, privileged, or internet-facing
- the same actor also changed SPN or ACL-related attributes nearby in time

---

## 3) SPN added to a user account

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.ObjectClass:"user" and
winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```

### What this finds
SPN values added to **user objects**.

### What to look for if this returns results
Review:

- whether the modified account is a normal user or service account
- whether the account is privileged
- the SPN string in `AttributeValue`
- whether the SPN matches a real application or service

### Investigate further when
- a normal user suddenly gets an SPN
- the account is privileged
- the account has weak password hygiene or old passwords
- the change was not part of a documented app deployment

---

## 4) Shadow Credentials

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"
```

### What this finds
New values added to `msDS-KeyCredentialLink`, the key attribute used in **Shadow Credentials** abuse.

### What to look for if this returns results
Review:

- whether the affected object is a user or computer
- whether the modifying account is expected to manage key trust / identity sync
- whether the change touches a privileged account
- whether the value lines up with a legitimate provisioning workflow

### Investigate further when
- the modifying account is unexpected
- the target object is privileged
- the environment does not normally use this feature for the affected object type
- the change was followed by unusual logon behavior for that account

---

## 5) Delegation target changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:"msDS-AllowedToDelegateTo"
```

### What this finds
Changes to constrained delegation targets.

### What to look for if this returns results
Review:

- which account or computer was changed
- what new target service was added in `AttributeValue`
- whether the account is supposed to perform delegation
- whether the actor normally manages Kerberos delegation

### Investigate further when
- a non-service account receives delegation targets
- the new target points to sensitive services
- the change happened without a corresponding change ticket
- multiple delegation-related attributes changed together

---

## 6) gMSA password-reader exposure

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:"msDS-GroupMSAMembership"
```

### What this finds
Changes to who can retrieve the password of a **group Managed Service Account**.

### What to look for if this returns results
Review:

- which gMSA object changed
- what principal or group was added
- whether a broad group was added instead of a tightly scoped host set
- whether the gMSA runs privileged services

### Investigate further when
- a broad or nested group was added
- the new reader was not expected
- the gMSA supports sensitive systems or tier-0 services
- the actor is outside the server / IAM team

---

## 7) LAPS expiration manipulation

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.AttributeLDAPDisplayName:"ms-Mcs-AdmPwdExpirationTime"
```

### What this finds
Changes to the legacy LAPS password expiration time attribute.

### What to look for if this returns results
Review:

- whether the same actor changed many computers
- whether the change affected sensitive endpoints or servers
- whether expiration values were moved unexpectedly far out
- whether the actor is expected to manage LAPS

### Investigate further when
- there is no known LAPS maintenance activity
- a single actor changes many machines quickly
- sensitive systems are affected
- the same actor also changes other AD security-relevant attributes

---

## 8) `sAMAccountName` changes on computer objects

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.ObjectClass:"computer" and
winlog.event_data.AttributeLDAPDisplayName:"sAMAccountName"
```

### What this finds
Renames or account-name changes on computer objects.

### What to look for if this returns results
Review:

- the old and new machine identity context if available
- whether the new name resembles a legitimate host
- whether the new name follows normal conventions
- whether related DNS or SPN changes occurred around the same time

### Investigate further when
- the new name imitates a real server or domain controller
- the new name looks malformed or suspicious
- the change was not part of a rejoin / rebuild / migration
- other computer attributes changed together

---

## 9) `dNSHostName` and `msDS-AdditionalDnsHostName` changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.ObjectClass:"computer" and
winlog.event_data.AttributeLDAPDisplayName:("dNSHostName" or "msDS-AdditionalDnsHostName")
```

### What this finds
Hostname-related changes on computer objects.

### What to look for if this returns results
Review:

- the new hostname value
- whether the name belongs to a real production service
- whether it fits expected naming standards
- whether the same object also received SPN or delegation changes

### Investigate further when
- alternate hostnames appear unexpectedly
- the hostname suggests impersonation of a critical service
- the actor is not expected to manage computer objects
- multiple suspicious computer-object changes occur together

---

## 10) `userAccountControl` changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.AttributeLDAPDisplayName:"userAccountControl"
```

### What this finds
Changes to account-control flags on users or computers.

### What to look for if this returns results
Review:

- whether the target is a user, service account, or computer
- whether the target is privileged
- whether many changes were made by the same actor
- whether other account-related attributes changed nearby in time

### Investigate further when
- the account is privileged or sensitive
- the change weakens expected security posture
- the actor is not expected to manage that object
- the change coincides with SPN, delegation, or naming changes

---

## 11) `altSecurityIdentities` changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:"altSecurityIdentities"
```

### What this finds
Changes to alternate certificate / mapping identities.

### What to look for if this returns results
Review:

- whether the target is privileged
- the mapping value in `AttributeValue`
- whether the actor normally manages smart card or PKI integrations
- whether the mapping format matches your legitimate environment

### Investigate further when
- the mapping was unexpected
- the target account is privileged
- the actor is not part of PKI / IAM administration
- the environment has not recently rolled out certificate-authentication changes

---

## 12) `nTSecurityDescriptor` changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor"
```

### What this finds
ACL / security descriptor changes on AD objects.

### What to look for if this returns results
Prioritize objects such as:

- `CN=AdminSDHolder,CN=System,...`
- the domain root
- privileged groups
- privileged users
- certificate templates
- objects under Public Key Services

### Investigate further when
- the changed object is privileged
- the actor is unexpected
- the change was not part of approved admin work
- the same actor changed multiple high-value objects

### Why this is high priority
This is one of the most important 5136 detections because dangerous rights can be added here and abused later.

---

## 13) AdminSDHolder changes

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.ObjectDN:"CN=AdminSDHolder,CN=System*"
```

### What this finds
Any audited change to the **AdminSDHolder** object.

### What to look for if this returns results
Review:

- whether `nTSecurityDescriptor` changed
- who made the change
- whether the time matches an approved hardening activity
- whether protected groups or accounts changed soon after

### Investigate further when
- the actor is unexpected
- no approved change explains it
- the modification affects permissions
- protected accounts begin showing related 5136 or privilege changes afterward

---

## 14) GPO abuse indicators

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.ObjectClass:"groupPolicyContainer"
```

### What this finds
Changes to Group Policy objects.

### What to look for if this returns results
Review:

- the GPO object in `ObjectDN`
- who changed it
- whether the change happened during normal GPO administration
- nearby file-level changes in SYSVOL

### Investigate further when
- the actor is not a normal GPO admin
- the GPO is linked broadly
- the change is followed by endpoint execution or scheduled task activity
- there are related SYSVOL file changes such as scripts or task XML

---

## 15) `msDS-SupportedEncryptionTypes`

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.AttributeLDAPDisplayName:"msDS-SupportedEncryptionTypes"
```

### What this finds
Changes to Kerberos encryption type settings on an account.

### What to look for if this returns results
Review:

- whether the account is a service account or privileged account
- whether the actor is expected to modify Kerberos settings
- whether the change happened during a hardening or migration project
- whether authentication alerts started soon after

### Investigate further when
- the account is sensitive
- the change weakens expected encryption posture
- the actor is unexpected
- the change appears alongside SPN, delegation, or service-account changes

---

## 16) High-risk watchlist query

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674" and
winlog.event_data.AttributeLDAPDisplayName:(
  "nTSecurityDescriptor" or
  "msDS-AllowedToActOnBehalfOfOtherIdentity" or
  "servicePrincipalName" or
  "msDS-KeyCredentialLink" or
  "msDS-AllowedToDelegateTo" or
  "msDS-GroupMSAMembership" or
  "ms-Mcs-AdmPwdExpirationTime" or
  "userAccountControl" or
  "sAMAccountName" or
  "dNSHostName" or
  "msDS-AdditionalDnsHostName" or
  "altSecurityIdentities" or
  "msDS-SupportedEncryptionTypes"
)
```

### What this finds
A compact watchlist of the highest-value 5136 attribute changes.

### What to look for if this returns results
Prioritize hits by:

1. privileged object changed
2. unusual actor
3. risky attribute
4. suspicious new value
5. multiple related changes in one session

### Investigate further when
- the same actor modified multiple sensitive objects
- the changed object is tier-0 or PKI-related
- the value clearly introduces new access or authentication paths
- the activity does not match approved change work

---

## Important note on `primaryGroupID`

Do not rely on 5136 as your main signal for `primaryGroupID` changes. Use:

- **4738** for users
- **4742** for computers

for better visibility into primary-group changes.

---

## Suggested triage checklist for any hit

When any query returns results, answer these questions:

1. Who made the change?
2. What object changed?
3. What attribute changed?
4. What was the new value?
5. Is the object privileged or sensitive?
6. Was the change expected and documented?
7. Did the same actor make other risky changes nearby in time?
8. Are there related events such as 4624, 4662, 4738, 4742, or SYSVOL file activity?
