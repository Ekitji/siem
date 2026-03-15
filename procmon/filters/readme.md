# Filters
My favorite is Filter 1 which shows you lots of event and helps you backtrack possible privilege escalation. 
Most of the relevant events is captured. If you find something interesting you could use "Process tree" to have parent/child relations.
Procmon --> Tools --> Process tree
You can do this on you captured .PML File also after querying in the SIEM.

## Filter 1 
SYSTEM AND Operation NOT Reg*
#### Generates lots of events but excludes registry related events. Shows possible file replacements or file planting for privilege escalation. Look for DLL and EXE.

## Filter 2
SYSTEM AND Operation NOT Reg* AND Result * NOT FOUND
#### Focuses on files that are missing. Possible DLL/EXE planting for privilege escalation.


## Filter 3
SYSTEM AND Operation NOT Reg* AND Result * NOT FOUND AND Path (Programdata OR Temp OR C:\Users)
#### Focuses on files that are missing. Possible DLL/EXE planting for privilege escalation. Focus on User-writable paths.

## PrivEsc
NOT FOUND AND Directory whitelisting
#### Generic from https://github.com/CERTCC/privesc

