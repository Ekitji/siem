# Arbitrary File Write
- Overwrite a file
- Drop a file where it can be used for DLL Hijacking
- We must be able to control the content or
- the file write shall mess the ACL and give over permissive ACL.
> Common with log files

# Arbitrary File Delete
- Remove files that we can replace
* C:\ProgramData
* C:\Windows\Temp
> Default rights allow low privileged users to create files and directories but not to modify existing ones.



