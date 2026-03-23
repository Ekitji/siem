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
