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
