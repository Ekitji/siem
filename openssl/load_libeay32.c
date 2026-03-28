#include <windows.h>
#include <stdio.h>

typedef int  (*SSL_library_init_fn)(void);
typedef void (*SSL_load_error_strings_fn)(void);
typedef void (*OPENSSL_add_all_algorithms_fn)(void);
typedef void (*ENGINE_load_dynamic_fn)(void);
typedef void (*ENGINE_load_builtin_engines_fn)(void);
typedef void (*OPENSSL_config_fn)(const char *appname);
typedef int  (*ENGINE_register_all_complete_fn)(void);

int main(void)
{
    printf("=================================================\n");
    printf(" libeay32.dll Loader\n");
    printf("=================================================\n\n");

    /* Step 1 - Load libeay32.dll */
    printf("[*] Step 1: Loading libeay32.dll...\n");
    HMODULE hLib = LoadLibraryA("libeay32.dll");
    if (hLib == NULL) {
        fprintf(stderr, "[!] Failed to load libeay32.dll (error %lu)\n", GetLastError());
        return 1;
    }
    printf("[+] libeay32.dll loaded. Handle: %p\n\n", (void*)hLib);

    /* Step 2 - Resolve function pointers */
    printf("[*] Step 2: Resolving OpenSSL function pointers...\n");

    SSL_library_init_fn p_SSL_library_init =
        (SSL_library_init_fn) GetProcAddress(hLib, "SSL_library_init");
    printf("[%c] SSL_library_init\n",            p_SSL_library_init ? '+' : '!');

    SSL_load_error_strings_fn p_SSL_load_error_strings =
        (SSL_load_error_strings_fn) GetProcAddress(hLib, "SSL_load_error_strings");
    printf("[%c] SSL_load_error_strings\n",       p_SSL_load_error_strings ? '+' : '!');

    OPENSSL_add_all_algorithms_fn p_OPENSSL_add_all_algorithms =
        (OPENSSL_add_all_algorithms_fn) GetProcAddress(hLib, "OPENSSL_add_all_algorithms");
    printf("[%c] OPENSSL_add_all_algorithms\n",   p_OPENSSL_add_all_algorithms ? '+' : '!');

    ENGINE_load_dynamic_fn p_ENGINE_load_dynamic =
        (ENGINE_load_dynamic_fn) GetProcAddress(hLib, "ENGINE_load_dynamic");
    printf("[%c] ENGINE_load_dynamic\n",          p_ENGINE_load_dynamic ? '+' : '!');

    ENGINE_load_builtin_engines_fn p_ENGINE_load_builtin_engines =
        (ENGINE_load_builtin_engines_fn) GetProcAddress(hLib, "ENGINE_load_builtin_engines");
    printf("[%c] ENGINE_load_builtin_engines\n",  p_ENGINE_load_builtin_engines ? '+' : '!');

    OPENSSL_config_fn p_OPENSSL_config =
        (OPENSSL_config_fn) GetProcAddress(hLib, "OPENSSL_config");
    printf("[%c] OPENSSL_config\n",               p_OPENSSL_config ? '+' : '!');

    ENGINE_register_all_complete_fn p_ENGINE_register_all_complete =
        (ENGINE_register_all_complete_fn) GetProcAddress(hLib, "ENGINE_register_all_complete");
    printf("[%c] ENGINE_register_all_complete\n", p_ENGINE_register_all_complete ? '+' : '!');
    printf("\n");

    /* Step 3 - Basic OpenSSL init */
    printf("[*] Step 3: Initializing OpenSSL...\n");
    if (p_SSL_library_init)           p_SSL_library_init();
    if (p_SSL_load_error_strings)     p_SSL_load_error_strings();
    if (p_OPENSSL_add_all_algorithms) p_OPENSSL_add_all_algorithms();
    printf("[+] Done.\n\n");

    /* Step 4 - Load dynamic engine support BEFORE config is parsed */
    printf("[*] Step 4: Loading dynamic engine support...\n");
    printf("[*]         (must happen before openssl.cnf is parsed)\n");
    if (p_ENGINE_load_dynamic)         p_ENGINE_load_dynamic();
    if (p_ENGINE_load_builtin_engines) p_ENGINE_load_builtin_engines();
    printf("[+] Done.\n\n");

    /* Step 5 - Trigger OPENSSLDIR config load */
    printf("[*] Step 5: Triggering OPENSSLDIR config load...\n");
    printf("[*]         OpenSSL reads openssl.cnf from the path\n");
    printf("[*]         hardcoded in libeay32.dll at build time.\n");
    printf("[*]         Expected: C:\\usr\\local\\ssl\\openssl.cnf\n");
    if (p_OPENSSL_config) {
        p_OPENSSL_config(NULL);
        printf("[+] OPENSSL_config() returned.\n\n");
    } else {
        printf("[!] OPENSSL_config not found in DLL.\n\n");
    }

    /* Step 6 - Register all engines so dynamic engine from config activates */
    printf("[*] Step 6: ENGINE_register_all_complete()...\n");
    printf("[*]         This activates the engine loaded from openssl.cnf.\n");
    if (p_ENGINE_register_all_complete) {
        p_ENGINE_register_all_complete();
        printf("[+] Done.\n\n");
    } else {
        printf("[!] Not available.\n\n");
    }

    printf("=================================================\n");
    printf(" Complete. test.dll loaded via openssl.cnf.\n");
    printf(" Check C:\\usr\\local\\ssl\\test.txt for log output.\n");
    printf("=================================================\n");
    printf("\nPress Enter to unload and exit...\n");
    getchar();

    FreeLibrary(hLib);
    return 0;
}
