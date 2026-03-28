# What each file contains
## OpenSSL_Binaries.md
File names, File versions, SHA1 hashes, OPENSSLDIR, ENGINESDIR AND MODULESDIR of many OpenSSL DLLs

## knownvulnerablepaths.md
Shows common vulnerable paths in OPENSSLDIR AND short about ENGINESDIR and MODULESDIR

## libeay32_test_dll.cpp
Code for a test.dll you can point openssl.cnf to load.
Pre-compiled is also uploaded here.

## openssl.cnf
Used with libeay32.dll pointing to /usr/local/ssl which is translated in windows to c:\usr\local\ssl
openssl.cnf in c:\usr\local\ssl
> Probably need adjustment to work with newer versions of OpenSSL.

## openssldir_check.cpp
Code for openssldir_check binary that checks OPENSSLDIR and ENGINESDIR
use Script to cover MODULESDIR also.

## openssldir_check_x64.exe
Pre-compiled 64-bit binary to use against OpenSSL DLL to fetch OPENSSLDIR and ENGINESDIR

## openssldir_check_x86.exe
Pre-compiled 32-bit binary to use against OpenSSL DLL to fetch OPENSSLDIR and ENGINESDIR

## test.dll
pre-compiled test.dll to use with libeay32.dll. Code from libeay32_test_dll.cpp.

> Execution chain will be, process --> libeay32.dll --> openssl.cnf --> test.dll
> the test.dll writes to c:\temp\test.txt

## test2.dll - rename so it fits the openssl.cnf
pre-compiled test.dll to use with libeay32.dll
> Execution chain will be, process --> libeay32.dll --> openssl.cnf --> test.dll
> the test2.dll writes to c:\usr\local\ssl\test.txt

# Pre-compiled opendirssl_checker files AND Powershell script
### Updated Opendirssl_checker for better compatibility with newer OpenSSL versions.
#### Original project
- https://github.com/mirchr/openssldir_check


## Running the executable against a Libcrypto related DLL
### Observe the returned Dir OPENSSLDIR pointing to /usr/local/ssl file path
`openssldir_check_x86.exe libeay32.dll`
```
openssldir_check v3.1 (all OpenSSL versions + deep scan)
Original: Rich Mirch @0xm1rch | Updated: deep scan edition
Running as: 32-bit

Detected OpenSSL major version: 1.x

[OpenSSL < 1.1 - SSLeay_version()]
  Version : OpenSSL 1.0.1g 7 Apr 2014
  Dir     : OPENSSLDIR: "/usr/local/ssl"

[Binary Scan]
  OPENSSLDIR tag  : "/usr/local/ssl"
                    -> Does NOT exist (can be created!)
  Path string     : "/usr/local/ssl"
  Path string     : "/usr/local/ssl/private"
  Path string     : "/usr/local/ssl/certs"
  Path string     : "/usr/local/ssl/cert.pem"
  Path string     : "/usr/local/ssl/lib/engines"
```

### Observe the returned DIR OPENSSLDIR pointing to C:\Program Files (x86)\Common Files\SSL which is a protected path if the ACL is correct.
`openssldir_check_x86.exe libcrypto-3.dll`
```
openssldir_check v3.1 (all OpenSSL versions + deep scan)
Original: Rich Mirch @0xm1rch | Updated: deep scan edition
Running as: 32-bit

Detected OpenSSL major version: 3.x

[OpenSSL 1.1+ / 3.x - OpenSSL_version()]
  Version : OpenSSL 3.6.1 27 Jan 2026
  Dir     : OPENSSLDIR: "C:\Program Files (x86)\Common Files\SSL"

[Binary Scan]
  OPENSSLDIR tag  : "C:\Program Files (x86)\Common Files\SSL"
                    -> EXISTS on this system
  ENGINESDIR tag  : "C:\Program Files (x86)\OpenSSL\lib\engines-3"

Tip: Run with --deep for XOR/Unicode/entropy obfuscation scan

[Writability Check]
  Not found  : C:\OpenSSL  (creatable by non-admin?)
  Not found  : C:\OpenSSL-Win32  (creatable by non-admin?)
  Not found  : C:\OpenSSL-Win64  (creatable by non-admin?)
  Protected  : C:\Program Files (x86)\Common Files\SSL
  Not found  : C:\Program Files (x86)\OpenSSL\lib\engines-3  (creatable by non-admin?)
  Not found  : C:\Program Files (x86)\OpenSSL\lib\ossl-modules  (creatable by non-admin?)
  Not found  : C:\etc\ssl  (creatable by non-admin?)
  Not found  : C:\usr\local\ssl  (creatable by non-admin?)
  Not found  : C:\usr\ssl  (creatable by non-admin?)
```

### Observe the returned DIR OPENSSLDIR pointing to c:/vsttech\vsttech\openssl/ssl which is a typical User-writable path.
`openssldir_check_x64.exe libeay64.dll`
```
openssldir_check v3.1 (all OpenSSL versions + deep scan)
Original: Rich Mirch @0xm1rch | Updated: deep scan edition
Running as: 64-bit

Detected OpenSSL major version: 0.x

[OpenSSL < 1.1 - SSLeay_version()]
  Version : OpenSSL 0.9.8o 01 Jun 2010
  Dir     : OPENSSLDIR: "c:/vsttech\vsttech\openssl/ssl"

[Binary Scan]
  OPENSSLDIR tag  : "c:/vsttech\vsttech\openssl/ssl"
                    -> Does NOT exist (can be created!)

Tip: Run with --deep for XOR/Unicode/entropy obfuscation scan

[Writability Check]
  Not found  : /dev/ubskey  (creatable by non-admin?)
  Not found  : C:\OpenSSL  (creatable by non-admin?)
  Not found  : C:\OpenSSL-Win32  (creatable by non-admin?)
  Not found  : C:\OpenSSL-Win64  (creatable by non-admin?)
  Not found  : C:\etc\ssl  (creatable by non-admin?)
  Not found  : C:\usr\local\ssl  (creatable by non-admin?)
  Not found  : C:\usr\ssl  (creatable by non-admin?)
  Not found  : c:/vsttech\vsttech\openssl/lib/engines  (creatable by non-admin?)
  Not found  : c:/vsttech\vsttech\openssl/ssl  (creatable by non-admin?)
  Not found  : c:/vsttech\vsttech\openssl/ssl/certs  (creatable by non-admin?)
  Not found  : c:/vsttech\vsttech\openssl/ssl/private  (creatable by non-admin?)
```


# PowerShell OpenSSL DLL Scanner

Quick PowerShell alternatives to `openssldir_check` for finding the `OPENSSLDIR` path baked into any OpenSSL DLL.  
Works on **all OpenSSL versions** regardless of exported function names.

---

## Method 1 — Find OPENSSLDIR tag directly - Works with easy CLEAN Output

```powershell
$dll = "C:\path\to\libcrypto.dll"
$bytes = [System.IO.File]::ReadAllBytes($dll)
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)

# Find OPENSSLDIR and ENGINESDIR tags
[regex]::Matches($text, '(OPENSSLDIR|ENGINESDIR|MODULESDIR): "([^"]+)"') |
    ForEach-Object { $_.Value }
```

**Example output:**
```
OPENSSLDIR: "C:\Program Files (x86)\Common Files\SSL"
ENGINESDIR: "C:\Program Files (x86)\OpenSSL\lib\engines-3"
```
##### As One-Liner for PWD (Print Working Directory/Current Working Directory) in Powershell
```
[regex]::Matches([System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes("$PWD\libcrypto-1_1-x64.dll")), '(OPENSSLDIR|ENGINESDIR|MODULESDIR): "([^"]+)"') | ForEach-Object { $_.Value }
```
> (Get-FileHash -Algorithm SHA1 ".\libcrypto-3.dll").Hash.ToLower()
---

## Method 2 — Scan for all SSL-relevant path strings (clean output)

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\libcrypto.dll")
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)

# Build artifact extensions to exclude
$excludeExts = '\.c$|\.h$|\.cpp$|\.pdb$|\.inc$|\.obj$|\.lib$|\.asm$|\.map$|\.rc$'

# Windows paths: require at least one proper folder segment (no garbage like T:\:d:l)
$winPattern  = '[A-Za-z]:\\(?:[A-Za-z0-9 _.()-]+\\)*[A-Za-z0-9 _.()-]+'

# Unix paths: require at least two proper segments of 2+ lowercase letters/digits
$unixPattern = '/[a-z][a-z0-9_-]+(?:/[a-z][a-z0-9_.-]+)+'

[regex]::Matches($text, "$winPattern|$unixPattern") |
    ForEach-Object { $_.Value.TrimEnd('"') } |
    Where-Object {
        $_ -notmatch $excludeExts  # exclude source/build files
    } |
    Sort-Object -Unique
```

**Example output:**
```
C:\Program Files (x86)\Common Files\SSL
C:\Program Files (x86)\OpenSSL\lib\engines-3
C:\Program Files (x86)\OpenSSL\lib\ossl-modules
/usr/local/ssl
```

---

## Method 3 — Full scanner with writability check

Save as `scan-openssldir.ps1`:

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$DllPath
)

$bytes = [System.IO.File]::ReadAllBytes($DllPath)
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)

# Build artifact extensions to filter out
$excludeExts = '\.c$|\.h$|\.cpp$|\.pdb$|\.inc$|\.obj$|\.lib$|\.asm$|\.map$|\.rc$|\.def$'

# Strict path patterns - require real folder segment names
$winPattern  = '[A-Za-z]:\\(?:[A-Za-z0-9 _.()-]+\\)*[A-Za-z0-9 _.()-]+'
$unixPattern = '/[a-z][a-z0-9_-]+(?:/[a-z][a-z0-9_.-]+)+'

Write-Host ""
Write-Host "OpenSSL DLL Scanner (PowerShell)" -ForegroundColor Cyan
Write-Host "DLL: $DllPath"
Write-Host ""

# 1. OPENSSLDIR / ENGINESDIR tags (most reliable)
Write-Host "[Tagged Paths]" -ForegroundColor Yellow
$tagged = [regex]::Matches($text, '(OPENSSLDIR|ENGINESDIR|MODULESDIR): "([^"]+)"')
if ($tagged.Count -gt 0) {
    $tagged | ForEach-Object { Write-Host "  $($_.Value)" -ForegroundColor Green }
} else {
    Write-Host "  No tagged paths found" -ForegroundColor DarkGray
}

# 2. All SSL-relevant path strings
Write-Host ""
Write-Host "[All Path Strings]" -ForegroundColor Yellow
$allPaths = [regex]::Matches($text, "$winPattern|$unixPattern") |
    ForEach-Object { $_.Value.TrimEnd('"') } |
    Where-Object { $_ -notmatch $excludeExts } |
    Sort-Object -Unique

if ($allPaths) {
    $allPaths | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
} else {
    Write-Host "  No path strings found" -ForegroundColor DarkGray
}

# 3. Writability check
# Combine found paths with common defaults
$defaultPaths = @(
    "C:\usr\local\ssl",
    "C:\etc\ssl",
    "C:\usr\ssl",
    "C:\OpenSSL",
    "C:\OpenSSL-Win32",
    "C:\OpenSSL-Win64"
)

# Extract just directory paths from found paths (no file extensions)
$dirPaths = $allPaths | Where-Object {
    $_ -notmatch '\.[a-zA-Z]{1,4}$' -and $_.Length -le 80
}

$checkPaths = ($defaultPaths + $dirPaths) | Sort-Object -Unique

Write-Host ""
Write-Host "[Writability Check]" -ForegroundColor Yellow
foreach ($p in $checkPaths) {
    if (Test-Path $p -PathType Container) {
        $testFile = Join-Path $p "~writetest.tmp"
        try {
            [System.IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -ErrorAction SilentlyContinue
            Write-Host "  WRITABLE   : $p  *** POTENTIAL RISK ***" -ForegroundColor Red
        } catch {
            Write-Host "  Protected  : $p" -ForegroundColor Green
        }
    } else {
        Write-Host "  Not found  : $p  (can be created!)" -ForegroundColor DarkYellow
    }
}
```

**Usage:**
```powershell
.\scan-openssldir.ps1 -DllPath "C:\Program Files (x86)\MyApp\libeay32.dll"
.\scan-openssldir.ps1 -DllPath "C:\Program Files (x86)\MyApp\libcrypto-3.dll"
```

---

## Compatibility

| OpenSSL Version | DLL Name | Works |
|---|---|---|
| 0.9.x | `libeay32.dll` | ✅ Binary scan |
| 1.0.x | `libeay32.dll` | ✅ Binary scan |
| 1.1.x | `libcrypto-1_1.dll` | ✅ Binary scan |
| 3.x | `libcrypto-3.dll` | ✅ Binary scan |
| Unknown/stripped | any | ✅ Binary scan |

> These scripts read the raw DLL bytes directly — no function calls, no bitness issues, no dependencies.

---

## Notes

- Run **as Administrator** if scanning DLLs in `Program Files`
- A path that **does not exist** is potentially exploitable — a low-privileged user may be able to create it and plant a malicious `openssl.cnf`
- Use openssldir_check binaries in repo for a more complete analysis including XOR obfuscation detection and PE entropy analysis if you dont get any results with the scripts.


# Libeay32 test.dll
**libeay32_test_dll.cpp**
Compiled with Microsoft Visual Studio.
Tested with libeay32.dll loading into a process. The test.dll will also be loaded into same process.
Outputs to c:\temp\test.txt - will create folder and file if missing. **the test2.dll will output to C:\usr\local\ssl\**

`Example output showing SYSTEM user code execution`
```
[2026-03-22 20:39:58] === DllMain: DLL_PROCESS_ATTACH ===
[2026-03-22 20:39:58] User: SYSTEM | Type: SYSTEM account
[2026-03-22 20:39:58] v_check() called
[2026-03-22 20:39:58] bind_engine() called - engine being bound
[2026-03-22 20:39:58] User: SYSTEM | Type: SYSTEM account
[2026-03-22 20:39:58] ENGINE API functions loaded from libeay32.dll
[2026-03-22 20:39:58] bind_engine() completed
[2026-03-22 20:39:58] engine_destroy() called
[2026-03-22 20:39:58] DllMain: DLL_PROCESS_DETACH
```


# load_libeay32.exe
A custom loader executable to mimic a legitimate process that loads the libeay32.dll --> loads openssl.cnf --> loads specified dll.
load_libeay32.c is the source code.
