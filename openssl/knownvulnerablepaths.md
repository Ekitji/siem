# Known Vulnerable Default Paths

> **Pro tip** Its more likely that you will find user-writable paths in the older/legacy versions of OpenSSL then the newer.

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

## My own list with DLLs, hashes and versions.

| Filename | Version | SHA1 hash| OPENSSLDIR | Application | ENGINES DIR |
|---|---|---|---|---|---|
| libcrypto-1_1-x64.dll | 1.1.1 | 3554f7e615496e4bebd30e24a3bcbe8752c1cd3b | "C:\Program Files\Common Files\SSL" | 
| libcrypto-1_1-x64.dll | 1.1.1n | 8ab148d18164ab411595d8bb2e9f2e6cea534948 | "C:\Program Files\Common Files\SSL" | PostgreSQL |
| libcrypto-1_1-x64.dll | 1.1.1w | 13423b30f73490fa93018e433f9b4c126e86c2c1 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-1_1-x64.dll | 1.1.1g | a6eb12db5d4bec6820d98058541973630a090b75 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-1_1-x64.dll | 1.1.1p | 585bac48084a1c40597a0f1a6c8cd8c135ea6b4a | "\apache24\conf" | Apache24 -IncB | |
| libcrypto-1_1.dll | 1.1.1w | e1e0e7884770b062b803b8396dfce08e889eadac | "C:\Program Files (x86)\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-1_1" |
| libcrypto-3.dll | 3.6.1 | fbfa3765ce078f67484e19e431b34fc7373fb36a | "C:\Program Files (x86)\Common Files\SSL" | |
| libcrypto-3.dll | 3.0.15 | 12d13a0f5e34820ad419e729a4541a32be81d728 | "C:\Program Files (x86)\Common Files\SSL" | |
| libcrypto-3.dll | 3.0.16 | 8bdaf2c1cebcc019d28ebf181de6751cad608ea4 |  "C:\Program Files (x86)\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-3" | 
| libcrypto-3-x64.dll | 3.0.15 | dd64e10b064efea5c6c1e01666f6c4f62c864e7a | "C:\Program Files\Common Files\SSL" | |
| libcrypto-3-x64.dll | 3.0.12 | 7b6ccb74ab9f28ed929d0e668b638b8bed375c20 | "C:\Program Files\Common Files\SSL" | |
| libcrypto-3-x64.dll | 3.0.16 | 9ec8b76179e2b746e0d0a6a8d8bf6e8f70729ede | "C:\Program Files\Common Files\SSL" | | "\builds\3rdparty\bash-packages\.package\lib\engines-3"| 8bdaf2c1cebcc019d28ebf181de6751cad608ea4 | "C:\Program Files (x86)\Common Files\SSL" | 
| libcrypto-3-x64.dll | 3.2.1 | ee6ed4b54daca2d787ad6232fd09701aafafd8b1 | "C:\Program Files\Common Files\SSL" | |
| libeay32.dll | 1.0.2p | b09bbc7f5f010ab1d750b5290cf331b372cd7fae | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2p | ad8950da5ad9a143a05ce84ddc41e0b7420079ef | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2p | fb3eebef898defba2bfd0dbc6167a9efcbe4ac8a |  | | 
| libeay32.dll | 1.0.2u | f684152c245cc708fbaf4d1c0472d783b26c5b18 | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2u | 3c9d8851721d2f1bc13a8dcb74549fa282a5a360 | "/usr/local/ssl" | | 
| libeay32.dll | 1.0.2t | 74fa885fa59fd7f5b1c71c7736566effbae86d63 |  "/usr/local/ssl" | |
| libeay32.dll | 1.0.1g | 4e5329c4321b17a54d40df6ff6d2537ebc54691b |  "/usr/local/ssl" | |
| libeay32.dll | 1.0.2ze | abb4d4b100aaa5c47ed7b16e9dcf729964b6a197 |"/builds/3rdparty/bash-packages/.package/ssl" | PNM | 
| libeay64.dll | 0.9.8o | c4157d4340118db638c615d5c8a81193bf241dd2 | "c:/vsttech\vsttech\openssl/ssl" | |


---
> **Pro Tip!** Have you found a DLL and have its hash and version? check below if its there and compare version and hash. If they match, use that DLL to look what OPENSSLDIR is set.

> **Plenty DLLS can be found here** https://github.com/IndySockets/OpenSSL-Binaries/tree/master

> Check Archive folder also for more versions in same and different ranges.
