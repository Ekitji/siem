# petodll.exe a tool to export a legitimate DLLs functions (Generates a stub DLL)
The tool exports a legitimate DLLs functions and creates a Visual Studio code project for compiling a own DLL which
when the DLL is attached, it writes a log file to c:\temp\test.txt with what process was executed, which dll was loaded and as what user. It has also a function for playing sound when 
DllMain is called.

**Usage**

> petodll.exe /path/to/real/dll

**Example**
> petodll.exe C:\Windows\System32\profapi.dll


### Created Visual studio project
The created visual studio project will be saved in same folder as petodll.exe with the DLLs file name as folder name.

# petodllproxy.dll a tool to export a legitimate DLLs functions (Generates a proxy DLL)


