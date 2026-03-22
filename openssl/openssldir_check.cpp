/* openssldir_check - Windows utility to check for potential insecure OPENSSLDIR paths built into OpenSSL libraries
*  Original Author: Rich Mirch @0xm1rch
*  Project: https://github.com/mirchr/openssldir_check
*  Updated: Added support for OpenSSL 3.x, binary scanning, and deep scan
*           for obfuscated/stripped/modified OpenSSL builds
*/

#define _CRT_SECURE_NO_WARNINGS
#include <cstring>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <math.h>

/* OpenSSL < 1.1 */
#define SSLEAY_VERSION  0
#define SSLEAY_DIR      5

/* OpenSSL 1.1.x / 3.x */
#define OPENSSL_VERSION_1_1  0
#define OPENSSL_DIR_1_1      4

using namespace std;

#ifdef _WIN64
    typedef const char*(__stdcall *f_SSLeay_version)(int);
    typedef const char*(__stdcall *f_OpenSSL_version)(int);
    typedef unsigned long(__stdcall *f_SSLeay)(void);
    typedef unsigned long(__stdcall *f_OpenSSL_version_num)(void);
    const unsigned int bits = 64;
#else
    typedef const char*(__cdecl *f_SSLeay_version)(int);
    typedef const char*(__cdecl *f_OpenSSL_version)(int);
    typedef unsigned long(__cdecl *f_SSLeay)(void);
    typedef unsigned long(__cdecl *f_OpenSSL_version_num)(void);
    const unsigned int bits = 32;
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */
static bool is_printable_path_char(char c)
{
    return (c >= 0x20 && c < 0x7F);
}

static bool looks_like_path(const string &s)
{
    if (s.length() < 4) return false;
    if (s[0] == '/') return true;
    if (s.length() >= 3 && isalpha((unsigned char)s[0]) &&
        s[1] == ':' && (s[2] == '\\' || s[2] == '/')) return true;
    return false;
}

static double calc_entropy(const char *buf, int len)
{
    if (len <= 0) return 0.0;
    int freq[256] = {};
    for (int i = 0; i < len; i++)
        freq[(unsigned char)buf[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / len;
        e -= p * log(p) / log(2.0);
    }
    return e;
}

/* ------------------------------------------------------------------ */
/* Detect OpenSSL major version                                       */
/* ------------------------------------------------------------------ */
int get_openssl_major(HINSTANCE hLib)
{
    f_OpenSSL_version_num ver_num =
        (f_OpenSSL_version_num)GetProcAddress(hLib, "OpenSSL_version_num");
    if (ver_num)
        return (int)(((unsigned long)ver_num() >> 28) & 0xF);

    f_SSLeay ssleay = (f_SSLeay)GetProcAddress(hLib, "SSLeay");
    if (ssleay)
        return (int)(((unsigned long)ssleay() >> 28) & 0xF);

    return -1;
}

/* ------------------------------------------------------------------ */
/* Standard binary scan                                               */
/* ------------------------------------------------------------------ */
void binary_scan(const vector<char> &buf)
{
    cout << "\n[Binary Scan]\n";
    long fsize = (long)buf.size();
    bool found = false;

    /* 1. OPENSSLDIR tag */
    const char *tag = "OPENSSLDIR: \"";
    int taglen = (int)strlen(tag);
    for (long i = 0; i < fsize - taglen; i++)
    {
        if (memcmp(&buf[i], tag, taglen) == 0)
        {
            string path;
            for (long j = i + taglen; j < fsize && buf[j] != '"' && buf[j] != '\0'; j++)
                path += buf[j];
            cout << "  OPENSSLDIR tag  : \"" << path << "\"\n";
            DWORD attr = GetFileAttributesA(path.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES)
                cout << "                    -> Does NOT exist (can be created!)\n";
            else if (attr & FILE_ATTRIBUTE_DIRECTORY)
                cout << "                    -> EXISTS on this system\n";
            found = true;
        }
    }

    /* 2. ENGINESDIR tag */
    const char *etag = "ENGINESDIR: \"";
    int etaglen = (int)strlen(etag);
    for (long i = 0; i < fsize - etaglen; i++)
    {
        if (memcmp(&buf[i], etag, etaglen) == 0)
        {
            string path;
            for (long j = i + etaglen; j < fsize && buf[j] != '"' && buf[j] != '\0'; j++)
                path += buf[j];
            cout << "  ENGINESDIR tag  : \"" << path << "\"\n";
            found = true;
        }
    }

    /* 3. Common SSL paths */
    const char *common_paths[] = {
        "/usr/local/ssl", "/etc/ssl", "/usr/ssl", "/etc/pki/tls",
        "C:/OpenSSL", "C:/openssl", "C:/usr/local/ssl",
        "C:\\OpenSSL", "C:\\usr\\local\\ssl",
        NULL
    };

    set<string> already_printed;
    for (int p = 0; common_paths[p] != NULL; p++)
    {
        const char *cp = common_paths[p];
        int cplen = (int)strlen(cp);
        for (long i = 0; i < fsize - cplen; i++)
        {
            if (memcmp(&buf[i], cp, cplen) == 0)
            {
                char prev = (i > 0) ? buf[i - 1] : 0;
                if (prev == '\0' || prev == '"' || prev == ' ' || i == 0)
                {
                    string path;
                    for (long j = i; j < fsize && buf[j] != '\0' && buf[j] != '"'; j++)
                        path += buf[j];
                    if (path.length() > 4 && already_printed.find(path) == already_printed.end())
                    {
                        cout << "  Path string     : \"" << path << "\"\n";
                        already_printed.insert(path);
                        found = true;
                    }
                }
            }
        }
    }

    if (!found)
        cout << "  Nothing found in standard binary scan\n";
}

/* ------------------------------------------------------------------ */
/* Deep scan                                                          */
/* ------------------------------------------------------------------ */
void deep_scan(const vector<char> &buf)
{
    cout << "\n[Deep Scan - Obfuscation Detection]\n";
    long fsize = (long)buf.size();
    bool found = false;

    /* ---- 1. Unicode UTF-16LE path scan ---- */
    cout << "  Scanning for Unicode (UTF-16LE) paths...\n";
    {
        const char *uprefixes[] = { "/usr", "/etc", "C:", NULL };
        set<string> uniprinted;
        for (int p = 0; uprefixes[p] != NULL; p++)
        {
            wstring wpfx;
            for (int k = 0; uprefixes[p][k]; k++)
                wpfx += (wchar_t)(unsigned char)uprefixes[p][k];

            const wchar_t *wp = wpfx.c_str();
            int wlen = (int)(wpfx.size() * sizeof(wchar_t));

            for (long i = 0; i < fsize - wlen; i++)
            {
                if (memcmp(&buf[i], wp, wlen) == 0)
                {
                    wstring wpath;
                    for (long j = i; j < fsize - 1; j += 2)
                    {
                        wchar_t wc = *(wchar_t *)&buf[j];
                        if (wc == 0 || wc > 0x7E) break;
                        wpath += wc;
                    }
                    if (wpath.length() > 4)
                    {
                        string narrow(wpath.begin(), wpath.end());
                        if (looks_like_path(narrow) &&
                            uniprinted.find(narrow) == uniprinted.end())
                        {
                            cout << "  Unicode path    : \"" << narrow << "\"\n";
                            uniprinted.insert(narrow);
                            found = true;
                        }
                    }
                }
            }
        }
    }

    /* ---- 2. XOR scan keys 1-255 ---- */
    cout << "  Scanning for XOR-obfuscated paths (keys 0x01-0xFF)...\n";
    {
        const char *targets[] = { "/usr/local/ssl", "OPENSSLDIR", "openssl.cnf", NULL };
        set<string> xorprinted;

        for (int t = 0; targets[t] != NULL; t++)
        {
            const char *target = targets[t];
            int tlen = (int)strlen(target);

            for (int key = 1; key <= 255; key++)
            {
                vector<char> xored(tlen);
                for (int k = 0; k < tlen; k++)
                    xored[k] = target[k] ^ (char)key;

                for (long i = 0; i < fsize - tlen; i++)
                {
                    if (memcmp(&buf[i], xored.data(), tlen) == 0)
                    {
                        string decoded;
                        for (long j = i; j < fsize; j++)
                        {
                            char c = buf[j] ^ (char)key;
                            if (c == '\0') break;
                            if (!is_printable_path_char(c)) break;
                            decoded += c;
                        }
                        if (decoded.length() >= (size_t)tlen &&
                            xorprinted.find(decoded) == xorprinted.end())
                        {
                            cout << "  XOR key=0x" << hex << key << dec
                                 << " decoded : \"" << decoded << "\"\n";
                            xorprinted.insert(decoded);
                            found = true;
                        }
                    }
                }
            }
        }
    }

    /* ---- 3. Reversed string scan ---- */
    cout << "  Scanning for reversed path strings...\n";
    {
        const char *rev_targets[] = {
            "lss/lacol/rsu/", "lss/cte/", "lss/rsu/",
            "lss\\lacol\\rsu\\c", NULL
        };
        for (int t = 0; rev_targets[t] != NULL; t++)
        {
            const char *rt = rev_targets[t];
            int rtlen = (int)strlen(rt);
            for (long i = 0; i < fsize - rtlen; i++)
            {
                if (memcmp(&buf[i], rt, rtlen) == 0)
                {
                    string rev;
                    for (long j = i; j < fsize && buf[j] != '\0'; j++)
                        rev += buf[j];
                    string normal(rev.rbegin(), rev.rend());
                    cout << "  Reversed string : \"" << normal << "\"\n";
                    found = true;
                }
            }
        }
    }

    /* ---- 4. Split string scan ---- */
    cout << "  Scanning for split/fragmented path strings...\n";
    {
        const char *frag1[] = { "/usr", "C:\\", "C:/", NULL };
        const char *frag2[] = {
            "/local/ssl", "usr\\local\\ssl", "usr/local/ssl",
            "/ssl", "OpenSSL", "etc/ssl", NULL
        };

        set<string> splitprinted;
        for (int a = 0; frag1[a] != NULL; a++)
        {
            for (int b = 0; frag2[b] != NULL; b++)
            {
                int l1 = (int)strlen(frag1[a]);
                int l2 = (int)strlen(frag2[b]);

                for (long i = 0; i < fsize - l1 - l2 - 8; i++)
                {
                    if (memcmp(&buf[i], frag1[a], l1) == 0)
                    {
                        for (int gap = 0; gap <= 8; gap++)
                        {
                            long j = i + l1 + gap;
                            if (j + l2 >= fsize) break;
                            if (memcmp(&buf[j], frag2[b], l2) == 0)
                            {
                                string combined = string(frag1[a]) + string(frag2[b]);
                                if (looks_like_path(combined) &&
                                    splitprinted.find(combined) == splitprinted.end())
                                {
                                    cout << "  Split string    : \"" << combined
                                         << "\" (gap=" << gap << " bytes)\n";
                                    splitprinted.insert(combined);
                                    found = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* ---- 5. PE section entropy analysis ---- */
    cout << "  Analysing PE sections for high entropy (encrypted data)...\n";
    {
        if (fsize > 0x40)
        {
            DWORD peOffset = *(DWORD *)&buf[0x3C];
            if (peOffset + 0x18 < (DWORD)fsize &&
                buf[peOffset] == 'P' && buf[peOffset + 1] == 'E')
            {
                WORD numSections = *(WORD *)&buf[peOffset + 0x06];
                WORD optHdrSize  = *(WORD *)&buf[peOffset + 0x14];
                DWORD sectionOffset = peOffset + 0x18 + optHdrSize;

                for (int s = 0; s < numSections && s < 96; s++)
                {
                    DWORD sOff = sectionOffset + s * 40;
                    if (sOff + 40 >= (DWORD)fsize) break;

                    char sname[9] = {};
                    memcpy(sname, &buf[sOff], 8);

                    DWORD rawSize   = *(DWORD *)&buf[sOff + 0x10];
                    DWORD rawOffset = *(DWORD *)&buf[sOff + 0x14];

                    if (rawOffset + rawSize > (DWORD)fsize || rawSize < 256) continue;

                    double e = calc_entropy(&buf[rawOffset], min((DWORD)4096, rawSize));
                    if (e > 7.0)
                    {
                        cout << "  High entropy    : section [" << sname << "]"
                             << " entropy=" << e
                             << " -> possible encrypted/compressed data\n";
                        found = true;
                    }
                }
            }
        }
    }

    /* ---- 6. SSL keyword string extraction ---- */
    cout << "  Extracting SSL/crypto related strings...\n";
    {
        const char *keywords[] = {
            "ssl", "SSL", "openssl", "OpenSSL", "OPENSSL",
            "cnf", "conf", "crypto", "engine", "ENGINE",
            "OPENSSLDIR", "ENGINESDIR", NULL
        };

        set<string> printed;
        string current;

        for (long i = 0; i <= fsize; i++)
        {
            char c = (i < fsize) ? buf[i] : 0;
            if (is_printable_path_char(c))
            {
                current += c;
            }
            else
            {
                if (current.length() >= 6 && current.length() < 120)
                {
                    for (int k = 0; keywords[k] != NULL; k++)
                    {
                        if (current.find(keywords[k]) != string::npos &&
                            printed.find(current) == printed.end())
                        {
                            cout << "  String match    : \"" << current << "\"\n";
                            printed.insert(current);
                            found = true;
                            break;
                        }
                    }
                }
                current.clear();
            }
        }
    }

    if (!found)
        cout << "  Deep scan found nothing - path may be fully obfuscated or absent\n";
}

/* ------------------------------------------------------------------ */
/* Writability check                                                  */
/* ------------------------------------------------------------------ */
void writability_check(const vector<char> &buf)
{
    cout << "\n[Writability Check]\n";

    set<string> candidate_paths;

    const char *defaults[] = {
        "C:\\usr\\local\\ssl", "C:\\etc\\ssl", "C:\\usr\\ssl",
        "C:\\OpenSSL", "C:\\OpenSSL-Win32", "C:\\OpenSSL-Win64",
        NULL
    };
    for (int i = 0; defaults[i]; i++)
        candidate_paths.insert(defaults[i]);

    /* Collect Windows paths from binary */
    long fsize = (long)buf.size();
    string current;
    for (long i = 0; i <= fsize; i++)
    {
        char c = (i < fsize) ? buf[i] : 0;
        if (is_printable_path_char(c))
            current += c;
        else
        {
            if (looks_like_path(current) && current.length() > 4)
                candidate_paths.insert(current);
            current.clear();
        }
    }

    for (const string &path : candidate_paths)
    {
        DWORD attr = GetFileAttributesA(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            string testfile = path + "\\~writetest.tmp";
            HANDLE hFile = CreateFileA(testfile.c_str(), GENERIC_WRITE, 0,
                NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                CloseHandle(hFile);
                cout << "  WRITABLE   : " << path << "  *** POTENTIAL RISK ***\n";
            }
            else
            {
                cout << "  Protected  : " << path << "\n";
            }
        }
        else if (attr == INVALID_FILE_ATTRIBUTES)
        {
            cout << "  Not found  : " << path << "  (creatable by non-admin?)\n";
        }
    }
}

/* ------------------------------------------------------------------ */
int wmain(int argc, wchar_t **argv)
{
    cout << "openssldir_check v3.0 (all OpenSSL versions + deep scan)\n";
    cout << "Original: Rich Mirch @0xm1rch | Updated: deep scan edition\n";
    cout << "Running as: " << bits << "-bit\n\n";

    if (argv[1] == NULL)
    {
        wcerr << "Usage: openssldir_check <path\\to\\libeay32.dll>            OpenSSL < 1.1\n";
        wcerr << "   or  openssldir_check <path\\to\\libcrypto-version.dll>   OpenSSL >= 1.1\n";
        wcerr << "   or  openssldir_check <path\\to\\libcrypto-3.dll>         OpenSSL 3.x\n";
        wcerr << "\nFlags:\n";
        wcerr << "   --deep    Enable deep scan (XOR, Unicode, entropy, strings)\n";
        wcerr << "\nWARNING: Do not use an untrusted path!\n";
        exit(EXIT_FAILURE);
    }

    bool do_deep = false;
    for (int i = 2; i < argc; i++)
        if (wcsncmp(argv[i], L"--deep", 6) == 0)
            do_deep = true;

    /* Load file into memory */
    FILE *fh = _wfopen(argv[1], L"rb");
    if (!fh)
    {
        wcerr << "Could not open file: " << argv[1] << "\n";
        return EXIT_FAILURE;
    }
    fseek(fh, 0, SEEK_END);
    long fsize = ftell(fh);
    rewind(fh);
    vector<char> filebuf(fsize);
    fread(filebuf.data(), 1, fsize, fh);
    fclose(fh);

    /* Try to load as DLL */
    HINSTANCE hLibModule = LoadLibraryW(argv[1]);
    if (!hLibModule)
    {
        DWORD err = GetLastError();
        if (err == ERROR_BAD_EXE_FORMAT)
        {
            wcout << "Error: Not a " << bits << "-bit library - ";
            wcout << (bits == 64 ? "try 32-bit tool\n" : "try 64-bit tool\n");
        }
        else
        {
            wcerr << "Could not load DLL (error=" << err << ") - scan only\n";
        }
        binary_scan(filebuf);
        if (do_deep) deep_scan(filebuf);
        else cout << "\nTip: Run with --deep for XOR/Unicode/entropy obfuscation scan\n";
        writability_check(filebuf);
        return EXIT_FAILURE;
    }

    /* Version detection */
    int major = get_openssl_major(hLibModule);
    cout << "Detected OpenSSL major version: ";
    if (major == -1) cout << "unknown\n";
    else             cout << major << ".x\n";

    /* OpenSSL < 1.1 */
    f_SSLeay_version SSLeay_version =
        (f_SSLeay_version)GetProcAddress(hLibModule, "SSLeay_version");
    if (SSLeay_version)
    {
        cout << "\n[OpenSSL < 1.1 - SSLeay_version()]\n";
        const char *ver = SSLeay_version(SSLEAY_VERSION);
        const char *dir = SSLeay_version(SSLEAY_DIR);
        if (ver) cout << "  Version : " << ver << "\n";
        if (dir) cout << "  Dir     : " << dir << "\n";
    }

    /* OpenSSL 1.1+ / 3.x */
    f_OpenSSL_version OpenSSL_version =
        (f_OpenSSL_version)GetProcAddress(hLibModule, "OpenSSL_version");
    if (OpenSSL_version)
    {
        cout << "\n[OpenSSL 1.1+ / 3.x - OpenSSL_version()]\n";
        const char *ver = OpenSSL_version(OPENSSL_VERSION_1_1);
        const char *dir = OpenSSL_version(OPENSSL_DIR_1_1);
        if (ver) cout << "  Version : " << ver << "\n";
        if (dir) cout << "  Dir     : " << dir << "\n";
    }

    if (!SSLeay_version && !OpenSSL_version)
    {
        cout << "\nNeither SSLeay_version() nor OpenSSL_version() found\n";
        cout << "Stripped or non-standard build - falling through to scans\n";
    }

    FreeLibrary(hLibModule);

    binary_scan(filebuf);

    if (do_deep)
        deep_scan(filebuf);
    else
        cout << "\nTip: Run with --deep for XOR/Unicode/entropy obfuscation scan\n";

    writability_check(filebuf);

    return EXIT_SUCCESS;
}
