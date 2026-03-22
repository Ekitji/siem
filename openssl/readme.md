# Pre-compiled checker files from
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
