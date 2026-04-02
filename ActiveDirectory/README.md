# AD 5136 Hunting Guide for Elastic

This repo contains practical Elastic queries for hunting **Active Directory misconfigurations and abuse paths** using **Windows Security Event ID 5136**.

## Files

- [`adqueries.md`](./adqueries.md) — KQL queries plus investigation notes for each detection.

## What Event ID 5136 is good for

Event ID **5136** records changes to audited Active Directory objects, including:

- the object that changed
- the LDAP attribute that changed
- the new or removed value
- the account that made the change

This makes it useful for detecting **newly introduced risky AD changes**, such as:

- delegation abuse
- Shadow Credentials
- suspicious SPN additions
- ACL / DACL changes
- GPO abuse paths
- computer object spoofing changes
- certificate mapping abuse
- gMSA / LAPS-related risky changes

## Important limitation

5136 is **not** a full historical vulnerability inventory.

If a dangerous AD permission or bad configuration was created earlier and has **not changed recently**, 5136 will not show it. Use it as a **change detection** source, not as your only AD security assessment method.

## Required logging setup

Before using these detections, make sure:

- **Audit Directory Service Changes** is enabled
- the relevant AD objects / attributes have the right **SACL / auditing** configured
- domain controller Security logs are ingested into Elastic

## Key 5136 fields to review

For every hit, start with:

- `winlog.event_data.SubjectUserName`
- `winlog.event_data.SubjectUserSid`
- `winlog.event_data.SubjectLogonId`
- `winlog.event_data.ObjectDN`
- `winlog.event_data.ObjectClass`
- `winlog.event_data.AttributeLDAPDisplayName`
- `winlog.event_data.AttributeValue`
- `winlog.event_data.OperationType`
- `winlog.event_data.OpCorrelationID`

## Base KQL

```kql
event.code:"5136" and
host.os.type:"windows" and
winlog.event_data.OperationType:"%%14674"
```

`%%14674` is the **Value Added** operation, which is usually the best starting point for detection.

## Query pack

Open [`adqueries.md`](./adqueries.md) for:

- KQL queries
- what each query detects
- what to look for when it returns results
- first triage steps

## Sources used

- Microsoft Event 5136 documentation
- TrustedSec *A Hitch-hacker's Guide to DACL-Based Detections* Parts 1A, 1B, 2, and 3
- Elastic prebuilt detection content relevant to SPN, Shadow Credentials, AdminSDHolder, and GPO abuse
