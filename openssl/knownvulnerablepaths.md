# Known Vulnerable Default Paths And DLLs

> **Pro tip** Its more likely that you will find user-writable paths in the older/legacy versions of OpenSSL then the newer.
> Check bottom for a list of enumerated DLLs and their OPENSSLDIR, hash and version.

> Have in mind that its possible to specify the OPENSSLDIR path when the DLL is compiled by using parameters “--openssldir” but this is something that oftenly missed.

| OPENSSLDIR Path (Windows) | OpenSSL Version(s) | Build Type |
|---|---|---|
| `C:\usr\local\ssl` | 1.0.2 (all), 1.1.0 mingw, 1.1.1 ≤1.1.1c | mingw + MSVC default |
| `C:\usr\local` | 1.1.0 ≤1.1.0k, 1.1.1 ≤1.1.1c | mingw cross-compile |
| `C:\etc\ssl` | 1.0.2 custom, 1.1.x Debian-style | Custom `--openssldir=/etc/ssl` |
| `C:\build_area\...` / `C:\build\...` | 1.0.x, 1.1.x (any) | CI/CD build artifact path baked in |
| `C:\msys64\usr\local\ssl` / `C:\msys2\...` | 1.0.2, 1.1.x, 3.x (MSYS2 builds) | MSYS2 native build |
| `C:\Program Files\Common Files\SSL` | 1.1.1d+, 3.0–3.2 | Native MSVC / Win installer |
| `C:\Program Files\OpenSSL\ssl` | 3.x (OSSL_WINCTX builds) | Registry-aware builds |
| `C:\tmp\build` / `/tmp/build` | 3.x (Linux, bundled) | Cross-platform CI build artifact |


## Table: With less common ones

| OPENSSLDIR Path | OpenSSL Version(s) | Example Binaries | Application / Source |
|---|---|---|---|
| `C:\OpenSSL-Win32\ssl` / `C:\OpenSSL-Win64\ssl` | 1.0.2, 1.1.1 | `libcrypto-1_1.dll`, `libssl-1_1.dll`, `openssl.exe` | Shining Light Productions OpenSSL installer |
| `C:\Apache24\conf\ssl` | 1.0.2, 1.1.1 | `httpd.exe`, `mod_ssl.so` | Apache HTTP Server (Apache Lounge builds) |
| `C:\nginx\ssl` | 1.1.x, 3.x | `nginx.exe` | Nginx Windows builds with custom OpenSSL |
| `C:\Program Files\Git\usr\ssl` | 1.1.1, 3.x | `git.exe`, `ssh.exe`, `libcrypto*.dll` | Git for Windows (MSYS2-based) |
| `C:\Strawberry\c\ssl` | 1.1.x | `perl.exe`, `libcrypto*.dll` | Strawberry Perl |
| `C:\Perl64\ssl` | 1.0.2 | `perl.exe`, `ssleay32.dll`, `libeay32.dll` | ActivePerl (legacy) |
| `C:\PythonXY\Library\ssl` | 1.1.1, 3.x | `python.exe`, `_ssl.pyd`, `libcrypto*.dll` | CPython (Windows builds) |
| `C:\Anaconda3\Library\ssl` | 1.1.1, 3.x | `python.exe`, `openssl.exe`, `libssl*.dll` | Anaconda / Miniconda |
| `C:\Windows\System32\OpenSSL` | varies | `libcrypto*.dll`, `libssl*.dll` | Custom enterprise deployment |
| `C:\Tools\OpenSSL\ssl` | any | `openssl.exe`, `libcrypto*.dll` | Portable / manually unpacked builds |
| `C:\opt\ssl` | 1.1.x, 3.x | `openssl.exe`, custom app binaries | Unix-style custom ports |
| `C:\vcpkg\installed\x64-windows\tools\openssl\ssl` | 1.1.1, 3.x | `openssl.exe`, `libcrypto*.dll` | vcpkg-managed dependencies |
| `C:\cygwin64\usr\ssl` | 1.1.x, 3.x | `cygwin1.dll`, `openssl.exe` | Cygwin environment |
| `C:\Users\<user>\AppData\Local\Programs\OpenSSL\ssl` | 3.x | `openssl.exe`, `libcrypto-3-x64.dll` | User-local OpenSSL install |
| `C:\Qt\Tools\OpenSSL\ssl` | 1.1.1, 3.x | `QtWebEngineProcess.exe`, `assistant.exe` | Qt SDK / Qt Installer |
| `C:\Docker\openssl\ssl` | 1.1.x, 3.x | extracted `libcrypto*.dll` | Docker container artifacts copied to host |
| `C:\Rust\openssl\ssl` | 1.1.1, 3.x | `app.exe`, `libcrypto*.dll` | Rust apps using `openssl-sys` (vendored) |
| `C:\Electron\resources\ssl` | 1.1.1, 3.x | `app.exe`, `chrome.dll`, `libcrypto*.dll` | Electron apps bundling OpenSSL |
| `C:\ProgramData\ssl` | any | `libssl*.dll`, `openssl.cnf` | Enterprise shared SSL configuration |

---


# OpenSSL OPENSSLDIR Risk Analysis (Windows)

## Key Observations

### 1. Most Common Path: `C:\usr\local\ssl`

`C:\usr\local\ssl` is almost certainly the **single most common vulnerable path**.

**Reason:**
- If `--openssldir` is not specified at build time, OpenSSL defaults to:

/usr/local/ssl

- This default applies across:
- All OpenSSL **1.0.x** builds
- All platforms, including **Windows**

**Impact:**
- OpenSSL **1.0.2** dominated for nearly a decade
- Most third-party software **did not override the default**
- Result: this path is widely embedded in binaries

**Reference:** CyberArk

---

### 2. Second Most Common Path: `C:\usr\local`

`C:\usr\local` is the **second most frequently observed path**.

**Reason:**
- Originates from:
- OpenSSL **1.1.0 / 1.1.1**
- **MinGW configuration targets**
- These builds assume a Unix-like environment and default:

prefix = /usr/local


**Reference:** Wietze Beukema

---

### 3. Debian-Style Path: `C:\etc\ssl`

This path is **rarer but historically significant**.

**Origin:**
- Cross-compilation from:
- Debian / Ubuntu systems
- These systems use:

/etc/ssl


**Notable Case:**
- Observed in the **PIA VPN vulnerability case**

---

### 4. Build Artifact Paths: `C:\build_area\...` / `C:\build\...`

These represent a **high-risk but low-probability scenario**.

**Risk:**
- Potential **privilege escalation vector**
- If writable and matched by attacker-controlled structure

**Limitation:**
- Requires:
- Exact directory structure to exist on target system
- Therefore:
- **Unlikely to be exploitable in practice**

---

### 5. OpenSSL 3.x Is Not Fully Fixed

Even in modern versions (e.g., **OpenSSL 3.5.0**), the issue persists.

#### MSYS2 Builds
- Still hardcode paths like:

C:/msys64/usr/local/ssl

- Confirmed via developer bug report (April 2025)

**Reference:** HackerOne

---

#### Native vs Cross-Compiled Builds

**Native MSVC builds:**
- Use:

%ProgramFiles%

- More secure default behavior

**Cross-compiled builds:**
- `--openssldir` refers to:
- The **target filesystem**, not the build host
- Leads to incorrect or unsafe embedded paths

**Reference:** Okta

---

### Structural Problem

Any **cross-compiled OpenSSL 3.x build** is still vulnerable if:

- `--openssldir` is **not explicitly set**, OR
- It points to a **non-protected path**

---

## Practical Hunting Strategy

### High-Yield Indicators

Focus on detecting these DLLs:

| OpenSSL Version | DLL Indicators |
|---|---|
| 1.0.x | `libeay32.dll`, `ssleay32.dll` |
| 1.1.x | `libcrypto-1_1*.dll`, `libssl-1_1*.dll` |

---

### Recommended Workflow

1. **Identify binaries** containing:
 - OpenSSL-related DLLs
2. Run:

openssldir_check

3. Extract and analyze embedded `OPENSSLDIR`

---

### High-Probability Targets

Applications that:
- Have **not been updated since ~2019**
- Bundle their own OpenSSL
- Are **not using system libraries**

**Conclusion:**
> These are highly likely to contain `C:\usr\local\ssl`

---

## Key Takeaway

- The default path:

C:\usr\local\ssl

dominates because:
- It was **never overridden in most builds**
- It persisted across **years of widely deployed OpenSSL versions**

- Even modern OpenSSL (3.x):
- Still suffers from **cross-compilation path leakage**

---

## Summary

| Path | Prevalence | Risk Level | Notes |
|---|---|---|---|
| `C:\usr\local\ssl` | Very High | High | Default across 1.0.x |
| `C:\usr\local` | High | Medium | MinGW builds |
| `C:\etc\ssl` | Medium | Medium | Debian-style builds |
| `C:\build\...` | Low | High | Requires matching structure |
| `C:\msys64\usr\local\ssl` | Medium | High | Still present in 3.x |

---

# OpenSSL MODULESDIR and Autoloaded DLLs

## 1. Context: MODULESDIR
- `MODULESDIR` is an environment variable (or compile-time path) that points to the directory where OpenSSL “modules” or providers are stored.
- A module in OpenSSL is usually a `.dll` (Windows) or `.so` (Linux) file that implements cryptographic algorithms or engine functionality.
- Examples: `aes.dll`, `rsa.dll`, `ec.dll`, or engine implementations.

## 2. OpenSSL 3.x Module Loading
OpenSSL 3 introduced a **provider concept**, where algorithms are implemented in providers rather than directly in `libcrypto`. The main providers are:

- **Default Provider (`default.dll`)** – provides most standard algorithms (AES, RSA, SHA, etc.).
- **Legacy Provider (`legacy.dll`)** – provides deprecated algorithms.
- **FIPS Provider (`fips.dll`)** – provides FIPS-compliant implementations (if built).

When OpenSSL starts:

1. It checks the compiled-in default path or the `OPENSSL_MODULES` environment variable (can be `MODULESDIR`) for DLLs.
2. It automatically loads:
   - `default.dll`
   - `legacy.dll` (optional)
   - `fips.dll` (if FIPS is enabled)

## 3. Autoload Behavior
From OpenSSL 3.0 documentation:

> OpenSSL automatically loads all providers found in `MODULESDIR` that match the expected provider interface unless explicitly disabled.

So practically, in Windows:
%MODULESDIR%\default.dll
%MODULESDIR%\legacy.dll
%MODULESDIR%\fips.dll


- Custom providers you place in `MODULESDIR` will also be autoloaded if they follow the naming and interface conventions.
- OpenSSL searches for `*.dll` and calls the provider entry point: `OSSL_provider_init`.

## ✅ Summary
DLLs autoloaded from `MODULESDIR` are:

- `default.dll` – standard algorithms.
- `legacy.dll` – deprecated algorithms.
- `fips.dll` – FIPS-compliant algorithms (if enabled).
- Any custom provider DLLs implementing the OpenSSL 3 module interface.

> If a DLL does not implement a provider interface, OpenSSL will ignore it.
>
### MODULESDIR → automatic loading of provider modules at OpenSSL startup.
 
### ENGINESDIR → manual loading of engines; not automatically autoloaded.
Engines are considered legacy in OpenSSL 3, while providers are the new modular system.


 ## Functions that has to be called to make the openssl.cnf read by the process.
| Missing function | What it does |
| --- | --- |
| `OPENSSL_config()` | The standard entry point that reads `openssl.cnf` |
| `CONF_modules_load_file()` | Explicit config file loader |
| `CONF_load()` | Lower-level config loader |
| `CONF_modules_load()` | Module-based config loader |
