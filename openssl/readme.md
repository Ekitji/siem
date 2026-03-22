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

Quick PowerShell alternatives to `openssldir_check` for finding the `OPENSSLDIR` path baked into any OpenSSL DLL.  
Works on **all OpenSSL versions** regardless of exported function names.

---

## Method 1 — Find OPENSSLDIR tag directly

```powershell
$dll = "C:\path\to\libcrypto.dll"
$bytes = [System.IO.File]::ReadAllBytes($dll)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)

# Find OPENSSLDIR string
$pattern = 'OPENSSLDIR[^\x00]*'
[regex]::Matches($text, $pattern) | ForEach-Object { $_.Value }
```

**Example output:**
```
OPENSSLDIR: "/usr/local/ssl"
```

---

## Method 2 — Scan for all path strings baked into the DLL

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\libcrypto.dll")
$text = [System.Text.Encoding]::ASCII.GetString($bytes)

# Look for Windows and Unix directory-like strings
[regex]::Matches($text, '[A-Za-z]:\\[^\x00]{3,50}|/[a-z]{2,}/[^\x00]{3,50}') |
    ForEach-Object { $_.Value } |
    Sort-Object -Unique
```

**Example output:**
```
/usr/local/ssl
C:\OpenSSL-Win32
```

---

## Method 3 — Full scanner with writability check

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$DllPath
)

$bytes = [System.IO.File]::ReadAllBytes($DllPath)
$text  = [System.Text.Encoding]::ASCII.GetString($bytes)

Write-Host "`nOpenSSL DLL Scanner (PowerShell)" -ForegroundColor Cyan
Write-Host "DLL: $DllPath`n"

# 1. OPENSSLDIR tag
Write-Host "[OPENSSLDIR Tag]" -ForegroundColor Yellow
$matches1 = [regex]::Matches($text, 'OPENSSLDIR[^\x00]{1,80}')
if ($matches1.Count -gt 0) {
    $matches1 | ForEach-Object { Write-Host "  $($_.Value)" -ForegroundColor Green }
} else {
    Write-Host "  Not found" -ForegroundColor Red
}

# 2. ENGINESDIR tag
Write-Host "`n[ENGINESDIR Tag]" -ForegroundColor Yellow
$matches2 = [regex]::Matches($text, 'ENGINESDIR[^\x00]{1,80}')
if ($matches2.Count -gt 0) {
    $matches2 | ForEach-Object { Write-Host "  $($_.Value)" -ForegroundColor Green }
} else {
    Write-Host "  Not found" -ForegroundColor Red
}

# 3. All path strings
Write-Host "`n[Path Strings]" -ForegroundColor Yellow
$paths = [regex]::Matches($text, '[A-Za-z]:\\[^\x00]{3,50}|/[a-z]{2,}/[^\x00]{3,50}') |
    ForEach-Object { $_.Value } |
    Sort-Object -Unique
if ($paths) {
    $paths | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
} else {
    Write-Host "  No path strings found" -ForegroundColor Red
}

# 4. Writability check
Write-Host "`n[Writability Check]" -ForegroundColor Yellow
$checkPaths = @(
    "C:\usr\local\ssl",
    "C:\etc\ssl",
    "C:\usr\ssl",
    "C:\OpenSSL",
    "C:\OpenSSL-Win32",
    "C:\OpenSSL-Win64"
)
# Also add any Windows paths found in the DLL
$paths | Where-Object { $_ -match '^[A-Za-z]:\\' } | ForEach-Object {
    $checkPaths += ($_ -split '[^\x00]')[0]
}

foreach ($p in ($checkPaths | Sort-Object -Unique)) {
    if (Test-Path $p) {
        # Try writing a temp file to test writability
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
- Use [openssldir_check](https://github.com/mirchr/openssldir_check) for a more complete analysis including XOR obfuscation detection and PE entropy analysis
