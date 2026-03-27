# Some DLLS to use..
> When NOT FOUND events is found in procmon

> procmon_details.png show example of Details and when the DLL is planted, it will probably get loaded to the process.


### Writes to c:\temp\test.txt
Many of the DLLs have exported functions from the real DLL. Try first with ctemptestplussound.dll and if its not working, you may need to export the functions and compile a own with the functions.


### ctemptestplussound.dll
Writes to C:\temp\test.txt and plays sound

### whomprogramdataplussound.exe
logs to C:\ProgramData\logs\
and plays sound

## PetoDLL
A tool to use to export functions from a legitimate DLL that you want to mimic and plant your own dll.
It gives you a visual studio project ready to compile the DLL.

