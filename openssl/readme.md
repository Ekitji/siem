# Pre-compiled checker files from
### Updated to be better compatible with newer OpenSSL versions.
- https://github.com/mirchr/openssldir_check


## Running the executable against a Libcrypto related DLL
### Observe the returned OPENSSLDIR pointing to a protected file path
`openssldir_check_x86.exe libcrypto-3.dll`
```
openssldir_check v1.0 by 0xm1rch

OpenSSL_version() returned OpenSSL 3.6.1 27 Jan 2026
OpenSSL_version() returned OPENSSLDIR: "C:\Program Files (x86)\Common Files\SSL"
```

### Observe the returned OPENSSLDIR pointing to a potential user-writable path.
`openssldir_check_x86.exe libeay32.dll`

```
openssldir_check v1.0 by 0xm1rch

SSLeay_version() returned OpenSSL 1.0.1g 7 Apr 2014
SSLeay_version() returned OPENSSLDIR: "/usr/local/ssl"
```


# PowerShell OpenSSL DLL Scanner
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
[regex]::Matches($text, '(OPENSSLDIR|ENGINESDIR): "([^"]+)"') |
    ForEach-Object { $_.Value }
```

**Example output:**
```
OPENSSLDIR: "C:\Program Files (x86)\Common Files\SSL"
ENGINESDIR: "C:\Program Files (x86)\OpenSSL\lib\engines-3"
```

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

## What was wrong with the original regex

The original pattern `[A-Za-z]:\\[^\x00]{3,50}` matched **any** byte sequence starting with a letter and `:\` — including binary data like:

```
T:\:d:l:t:|:?:?:?:?     <- binary garbage
E:\:c:w:1;A;Q;a;q        <- binary garbage  
q:\_Wc4?? j?????????     <- binary garbage
```

The fixed pattern requires **real folder segment names** — sequences of letters, digits, spaces, dots, and hyphens separated by backslashes — which eliminates all binary false positives.

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
- Use [openssldir_check](https://github.com/mirchr/openssldir_check) for a more complete analysis including XOR obfuscation detection and PE entropy analysis
