/* test_engine.c - No OpenSSL headers required
   Compile:
   cl /LD /W3 /MD test_engine.c /Fe:C:\temp\test.dll /link /MACHINE:X86
*/

#include <windows.h>
#include <stdio.h>
#include <time.h>

#define LOG_FILE "C:\\temp\\test.txt"

/* ------------------------------------------------------------------ */
/* Minimal OpenSSL ENGINE structs/macros for 1.0.1g - no headers needed */
/* ------------------------------------------------------------------ */
typedef struct engine_st ENGINE;

typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE*);
typedef int (*DYNAMIC_BIND_ENGINE)(ENGINE*, const char*);

/* ENGINE_CMD_DEFN - required by dynamic engine */
typedef struct {
    unsigned int cmd_num;
    const char* cmd_name;
    const char* cmd_desc;
    unsigned int cmd_flags;
} ENGINE_CMD_DEFN;

/* Dynamic engine check/bind magic numbers */
#define DYNAMIC_CHECK_MAGIC   0x9D6A7C8FL
#define DYNAMIC_BIND_MAGIC    0xAF3478B9L

typedef struct {
    unsigned long          check_magic;
    unsigned long          bind_magic;
    unsigned long          bind_version;
    DYNAMIC_BIND_ENGINE    bind_engine;
} dynamic_fns;

/* OpenSSL ENGINE API - imported from libeay32.dll */
typedef ENGINE* (*fn_ENGINE_new)(void);
typedef int     (*fn_ENGINE_free)(ENGINE*);
typedef int     (*fn_ENGINE_set_id)(ENGINE*, const char*);
typedef int     (*fn_ENGINE_set_name)(ENGINE*, const char*);
typedef int     (*fn_ENGINE_set_init_function)(ENGINE*, ENGINE_GEN_INT_FUNC_PTR);
typedef int     (*fn_ENGINE_set_finish_function)(ENGINE*, ENGINE_GEN_INT_FUNC_PTR);
typedef int     (*fn_ENGINE_set_destroy_function)(ENGINE*, ENGINE_GEN_INT_FUNC_PTR);

static fn_ENGINE_set_id              p_ENGINE_set_id = NULL;
static fn_ENGINE_set_name            p_ENGINE_set_name = NULL;
static fn_ENGINE_set_init_function   p_ENGINE_set_init_function = NULL;
static fn_ENGINE_set_finish_function p_ENGINE_set_finish_function = NULL;
static fn_ENGINE_set_destroy_function p_ENGINE_set_destroy_function = NULL;

/* ------------------------------------------------------------------ */
static void write_log(const char* message)
{
    FILE* f;
    time_t now;
    char timebuf[64];

    CreateDirectoryA("C:\\temp", NULL);

    f = fopen(LOG_FILE, "a");
    if (!f) return;

    time(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] %s\n", timebuf, message);
    fflush(f);
    fclose(f);
}

/* ------------------------------------------------------------------ */
static void log_user_context(void)
{
    HANDLE hToken = NULL;
    char msg[512];
    char username[256] = "<unknown>";
    DWORD unLen = sizeof(username);

    GetUserNameA(username, &unLen);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_USER* ptu = NULL;
        DWORD dwSize = 0;
        DWORD sessionId = 0;
        DWORD sidLen = sizeof(sessionId);

        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        ptu = (TOKEN_USER*)LocalAlloc(LPTR, dwSize);

        if (ptu && GetTokenInformation(hToken, TokenUser, ptu, dwSize, &dwSize))
        {
            BOOL isSystem = FALSE;
            BOOL isService = FALSE;
            BOOL isNetwork = FALSE;

            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            PSID pSystemSid = NULL;
            PSID pServiceSid = NULL;
            PSID pNetworkSid = NULL;

            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &pSystemSid);
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SERVICE_RID,
                0, 0, 0, 0, 0, 0, 0, &pServiceSid);
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_NETWORK_SERVICE_RID,
                0, 0, 0, 0, 0, 0, 0, &pNetworkSid);

            if (pSystemSid)  isSystem = EqualSid(ptu->User.Sid, pSystemSid);
            if (pServiceSid) isService = EqualSid(ptu->User.Sid, pServiceSid);
            if (pNetworkSid) isNetwork = EqualSid(ptu->User.Sid, pNetworkSid);

            FreeSid(pSystemSid);
            FreeSid(pServiceSid);
            FreeSid(pNetworkSid);

            GetTokenInformation(hToken, TokenSessionId,
                &sessionId, sidLen, &sidLen);

            if (isSystem)
                _snprintf(msg, sizeof(msg),
                    "User: %s | Type: SYSTEM account", username);
            else if (isService)
                _snprintf(msg, sizeof(msg),
                    "User: %s | Type: LOCAL SERVICE account", username);
            else if (isNetwork)
                _snprintf(msg, sizeof(msg),
                    "User: %s | Type: NETWORK SERVICE account", username);
            else if (sessionId == 0)
                _snprintf(msg, sizeof(msg),
                    "User: %s | Type: Service/non-interactive (session 0)", username);
            else
                _snprintf(msg, sizeof(msg),
                    "User: %s | Type: Interactive user (session %lu)", username, sessionId);

            LocalFree(ptu);
        }
        else
        {
            _snprintf(msg, sizeof(msg),
                "User: %s | Type: could not query token", username);
        }

        CloseHandle(hToken);
    }
    else
    {
        _snprintf(msg, sizeof(msg),
            "User: %s | Type: could not open token", username);
    }

    write_log(msg);
}

/* ------------------------------------------------------------------ */
static void load_engine_api(void)
{
    HMODULE hLib = GetModuleHandleA("libeay32.dll");
    if (!hLib)
    {
        write_log("WARNING: Could not get handle to libeay32.dll");
        return;
    }

    p_ENGINE_set_id = (fn_ENGINE_set_id)GetProcAddress(hLib, "ENGINE_set_id");
    p_ENGINE_set_name = (fn_ENGINE_set_name)GetProcAddress(hLib, "ENGINE_set_name");
    p_ENGINE_set_init_function = (fn_ENGINE_set_init_function)GetProcAddress(hLib, "ENGINE_set_init_function");
    p_ENGINE_set_finish_function = (fn_ENGINE_set_finish_function)GetProcAddress(hLib, "ENGINE_set_finish_function");
    p_ENGINE_set_destroy_function = (fn_ENGINE_set_destroy_function)GetProcAddress(hLib, "ENGINE_set_destroy_function");

    write_log("ENGINE API functions loaded from libeay32.dll");
}

/* ------------------------------------------------------------------ */
static int engine_init(ENGINE* e)
{
    write_log("=== engine_init() called ===");
    log_user_context();
    return 1;
}

static int engine_finish(ENGINE* e)
{
    write_log("engine_finish() called");
    return 1;
}

static int engine_destroy(ENGINE* e)
{
    write_log("engine_destroy() called");
    return 1;
}

/* ------------------------------------------------------------------ */
__declspec(dllexport)
int bind_engine(ENGINE* e, const char* id, const dynamic_fns* fns)
{
    write_log("bind_engine() called - engine being bound");
    log_user_context();

    load_engine_api();

    if (p_ENGINE_set_id)              p_ENGINE_set_id(e, "escalate");
    if (p_ENGINE_set_name)            p_ENGINE_set_name(e, "Escalate Test Engine");
    if (p_ENGINE_set_init_function)   p_ENGINE_set_init_function(e, engine_init);
    if (p_ENGINE_set_finish_function) p_ENGINE_set_finish_function(e, engine_finish);
    if (p_ENGINE_set_destroy_function)p_ENGINE_set_destroy_function(e, engine_destroy);

    write_log("bind_engine() completed");
    return 1;
}

__declspec(dllexport)
unsigned long v_check(unsigned long v)
{
    write_log("v_check() called");
    return DYNAMIC_CHECK_MAGIC;
}

/* ------------------------------------------------------------------ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        write_log("=== DllMain: DLL_PROCESS_ATTACH ===");
        log_user_context();
        break;
    case DLL_PROCESS_DETACH:
        write_log("DllMain: DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}
