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




## petodll version

Generates a stub DLL.

- Re-exports names and ordinals through the `.def`
- Non-forwarded exports are mostly empty `stub_N()` bodies
- It can log `DllMain`, and maybe log stub calls, but only when execution actually reaches those stub functions
- Forwarded exports usually bypass your code entirely

## petodllproxy  version

Generates a real proxy DLL.

- The proxy loads the original DLL at runtime
- Each function export goes through your code first
- Your code logs to `C:\temp\test.txt`, plays a sound, resolves the real function from the original DLL, then jumps to it
- That means you can observe many more function calls, including exports that were originally forwarders

## In practical terms

### petodll.exe

**Good for:** “make something that builds and exports the same names”

**Weak at:** “tell me exactly when exports are called”

### petodllproxy.exe

**Good for:** “detect DLL load and function usage while still passing execution to the real DLL”

**Better for:** `version.dll`-style interception and tracing

## Another way to think about it

### Stub

> “Pretend to be the DLL”

### Proxy

> “Stand in front of the real DLL”

