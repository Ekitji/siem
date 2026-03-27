#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <winreg.h>

#pragma comment(lib, "winmm.lib")

namespace fs = std::filesystem;

// ────────────────────────────────────────────────────────────────────────────
// Export entry — full PE export metadata
// ────────────────────────────────────────────────────────────────────────────
struct ExportEntry
{
    std::string name;           // public export name (may be empty)
    std::string forwardTarget;  // e.g. "NTDLL.RtlAllocateHeap" if forwarder
    DWORD       ordinal  = 0;   // actual ordinal value (Base + index)
    bool        hasName  = false;
    bool        isForwarder = false;
};

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────
static std::string Sanitize(const std::string& s)
{
    std::string out;
    for (unsigned char c : s)
        out += (std::isalnum(c) || c == '_') ? static_cast<char>(c) : '_';
    if (out.empty())  out = "unnamed";
    if (std::isdigit(static_cast<unsigned char>(out[0]))) out = "_" + out;
    return out;
}

// ────────────────────────────────────────────────────────────────────────────
// PE helpers — shared map/unmap logic
// ────────────────────────────────────────────────────────────────────────────
struct PEView
{
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    HANDLE  hMap  = nullptr;
    LPBYTE  base  = nullptr;
    bool    ok    = false;

    explicit PEView(const std::string& path)
    {
        hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;

        hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMap) { CloseHandle(hFile); return; }

        base = static_cast<LPBYTE>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!base) { CloseHandle(hMap); CloseHandle(hFile); return; }

        ok = true;
    }

    ~PEView()
    {
        if (base)  UnmapViewOfFile(base);
        if (hMap)  CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }

    DWORD RvaToOffset(DWORD rva, IMAGE_NT_HEADERS* nt) const
    {
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            DWORD start = sec[i].VirtualAddress;
            DWORD end   = start + (std::max)(sec[i].Misc.VirtualSize,
                                             sec[i].SizeOfRawData);
            if (rva >= start && rva < end)
                return sec[i].PointerToRawData + (rva - start);
        }
        return 0;
    }

    IMAGE_NT_HEADERS* NtHeaders() const
    {
        if (!ok) return nullptr;
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        return nt;
    }
};

// ────────────────────────────────────────────────────────────────────────────
// Parse full export table
// ────────────────────────────────────────────────────────────────────────────
static std::vector<ExportEntry> GetExports(const std::string& path)
{
    std::vector<ExportEntry> exports;
    PEView v(path);
    if (!v.ok) { std::cout << "[-] Cannot open: " << path << "\n"; return exports; }

    auto* nt = v.NtHeaders();
    if (!nt) { std::cout << "[-] Bad PE headers: " << path << "\n"; return exports; }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0)
    { std::cout << "[!] No export directory: " << path << "\n"; return exports; }

    DWORD exportOff = v.RvaToOffset(dir.VirtualAddress, nt);
    if (!exportOff) { std::cout << "[-] Export dir RVA not mapped\n"; return exports; }

    auto* ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(v.base + exportOff);
    if (ed->NumberOfFunctions == 0)
    { std::cout << "[!] Zero functions exported\n"; return exports; }

    DWORD funcOff = v.RvaToOffset(ed->AddressOfFunctions, nt);
    if (!funcOff) return exports;
    auto* funcRVAs = reinterpret_cast<DWORD*>(v.base + funcOff);

    DWORD* nameRVAs     = nullptr;
    WORD*  nameOrdinals = nullptr;
    if (ed->NumberOfNames > 0)
    {
        DWORD nOff = v.RvaToOffset(ed->AddressOfNames, nt);
        DWORD oOff = v.RvaToOffset(ed->AddressOfNameOrdinals, nt);
        if (nOff && oOff)
        {
            nameRVAs     = reinterpret_cast<DWORD*>(v.base + nOff);
            nameOrdinals = reinterpret_cast<WORD*>(v.base + oOff);
        }
    }

    // Build index->name map in one pass
    std::vector<std::string> nameByIdx(ed->NumberOfFunctions);
    std::vector<bool>        hasNameByIdx(ed->NumberOfFunctions, false);
    if (nameRVAs && nameOrdinals)
    {
        for (DWORD j = 0; j < ed->NumberOfNames; j++)
        {
            WORD idx = nameOrdinals[j];
            if (idx < ed->NumberOfFunctions)
            {
                DWORD noff = v.RvaToOffset(nameRVAs[j], nt);
                if (noff)
                {
                    nameByIdx[idx]    = reinterpret_cast<char*>(v.base + noff);
                    hasNameByIdx[idx] = true;
                }
            }
        }
    }

    DWORD exportDirStart = dir.VirtualAddress;
    DWORD exportDirEnd   = exportDirStart + dir.Size;

    for (DWORD i = 0; i < ed->NumberOfFunctions; i++)
    {
        DWORD rva = funcRVAs[i];
        if (rva == 0) continue; // null/gap slot

        ExportEntry e;
        e.ordinal = ed->Base + i;
        e.hasName = hasNameByIdx[i];
        if (e.hasName) e.name = nameByIdx[i];

        // Forwarder: function RVA falls inside the export directory
        if (rva >= exportDirStart && rva < exportDirEnd)
        {
            e.isForwarder = true;
            DWORD foff = v.RvaToOffset(rva, nt);
            if (foff)
                e.forwardTarget = reinterpret_cast<char*>(v.base + foff);
        }

        exports.push_back(e);
    }

    std::cout << "[+] " << path << " — " << exports.size() << " exports\n";
    return exports;
}

// ────────────────────────────────────────────────────────────────────────────
// Architecture
// ────────────────────────────────────────────────────────────────────────────
static std::string GetArch(const std::string& path)
{
    PEView v(path);
    auto* nt = v.NtHeaders();
    if (!nt) return "Win32";
    return (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? "x64" : "Win32";
}

// ────────────────────────────────────────────────────────────────────────────
// Toolset detection
// ────────────────────────────────────────────────────────────────────────────
static std::string DetectToolset()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Tools\\MSVC",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char name[256]; DWORD size = sizeof(name);
        if (RegEnumKeyExA(hKey, 0, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        { RegCloseKey(hKey); return "v143"; }
        RegCloseKey(hKey);
    }
    return "v142";
}

// ────────────────────────────────────────────────────────────────────────────
// GenCpp — minimal includes, stub_N internal names, no dllexport
// ────────────────────────────────────────────────────────────────────────────
static std::string GenCpp(const std::string& dllName,
                           const std::vector<ExportEntry>& exports)
{
    std::stringstream ss;

    // WIN32_LEAN_AND_MEAN deliberately limits what windows.h pulls in,
    // which avoids header declarations clashing with export names
    // (e.g. GetFileVersionInfoA from version.dll vs <winver.h>).
    ss << "#define NOMINMAX\n"
          "#define WIN32_LEAN_AND_MEAN\n"
          "#include <windows.h>\n"
          "#include <mmsystem.h>\n"
          "#pragma comment(lib, \"winmm.lib\")\n\n";

    ss << "static const char* g_DllName = \"" << dllName << "\";\n\n";

    ss << R"(// ── Logging ─────────────────────────────────────────────────────────────────
static void AppendLogLine(const char* line)
{
    CreateDirectoryA("C:\\temp", NULL);
    HANDLE h = CreateFileA("C:\\temp\\test.txt", FILE_APPEND_DATA, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        WriteFile(h, line, (DWORD)lstrlenA(line), &written, NULL);
        CloseHandle(h);
    }
}

static void Log(HMODULE hModule, const char* msg)
{
    SYSTEMTIME st; GetLocalTime(&st);

    char user[256] = "UNKNOWN";
    DWORD uSz = sizeof(user);
    GetUserNameA(user, &uSz);

    char exePath[MAX_PATH] = "UNKNOWN";
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char dllPath[MAX_PATH] = "UNKNOWN";
    GetModuleFileNameA(hModule, dllPath, MAX_PATH);

    char line[2048];
    wsprintfA(line,
        "[%04u-%02u-%02u %02u:%02u:%02u] DLL: %s | %s | User: %s | EXE: %s | DLL: %s\r\n",
        (unsigned)st.wYear, (unsigned)st.wMonth,  (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        g_DllName, msg ? msg : "?", user, exePath, dllPath);

    AppendLogLine(line);
}

static DWORD WINAPI PlayRing05Thread(LPVOID)
{
    Sleep(500);
    PlaySoundA("C:\\Windows\\Media\\Ring05.wav", NULL, SND_FILENAME | SND_SYNC);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Log(hModule, "Loaded");
        CreateThread(NULL, 0, PlayRing05Thread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        Log(hModule, "Unloaded");
    }
    return TRUE;
}

)";

    ss << "// ── Stubs (internal names only — .def owns all public export names) ─────────\n";
    for (size_t i = 0; i < exports.size(); ++i)
    {
        // Forwarders point at another DLL entirely — no stub body needed.
        if (!exports[i].isForwarder)
            ss << "extern \"C\" void stub_" << i << "() {}\n";
    }

    return ss.str();
}

// ────────────────────────────────────────────────────────────────────────────
// GenDef — alias, ordinals, NONAME, forwarders
// ────────────────────────────────────────────────────────────────────────────
static std::string GenDef(const std::string& dllName,
                           const std::vector<ExportEntry>& exports)
{
    std::stringstream ss;
    ss << "LIBRARY " << dllName << "\n";
    ss << "EXPORTS\n";

    for (size_t i = 0; i < exports.size(); ++i)
    {
        const auto& e = exports[i];

        if (e.isForwarder)
        {
            // Linker forwarder syntax: PublicName=Target.Symbol @ordinal
            if (e.hasName)
                ss << "    " << e.name << "=" << e.forwardTarget
                   << " @" << e.ordinal << "\n";
            else
                ss << "    " << e.forwardTarget
                   << " @" << e.ordinal << " NONAME\n";
        }
        else if (e.hasName)
        {
            // Named export aliased to safe internal stub
            ss << "    " << e.name << "=stub_" << i
               << " @" << e.ordinal << "\n";
        }
        else
        {
            // Ordinal-only export
            ss << "    stub_" << i << " @" << e.ordinal << " NONAME\n";
        }
    }

    return ss.str();
}

// ────────────────────────────────────────────────────────────────────────────
// GenVcxproj
// ────────────────────────────────────────────────────────────────────────────
static std::string GenVcxproj(const std::string& projectName,
                               const std::string& arch)
{
    std::string toolset = DetectToolset();
    std::stringstream ss;

    auto emitConfig = [&](const std::string& config)
    {
        bool dbg = (config == "Debug");
        ss << "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='"
           << config << "|" << arch << "'\">\n"
              "    <ClCompile>\n"
              "      <WarningLevel>Level3</WarningLevel>\n"
              "      <PreprocessorDefinitions>"
           << (dbg ? "_DEBUG" : "NDEBUG")
           << ";_WINDOWS;_USRDLL;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)"
              "</PreprocessorDefinitions>\n"
              "      <Optimization>" << (dbg ? "Disabled" : "MaxSpeed") << "</Optimization>\n"
              "      <RuntimeLibrary>" << (dbg ? "MultiThreadedDebug" : "MultiThreaded") << "</RuntimeLibrary>\n"
              "    </ClCompile>\n"
              "    <Link>\n"
              "      <SubSystem>Windows</SubSystem>\n"
              "      <AdditionalDependencies>winmm.lib;%(AdditionalDependencies)</AdditionalDependencies>\n"
              "      <ModuleDefinitionFile>" << projectName << ".def</ModuleDefinitionFile>\n"
              "    </Link>\n"
              "  </ItemDefinitionGroup>\n";
    };

    ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
          "<Project DefaultTargets=\"Build\" "
          "xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
          "  <ItemGroup Label=\"ProjectConfigurations\">\n";

    for (auto& c : { std::string("Debug"), std::string("Release") })
        ss << "    <ProjectConfiguration Include=\"" << c << "|" << arch << "\">\n"
              "      <Configuration>" << c << "</Configuration>\n"
              "      <Platform>" << arch << "</Platform>\n"
              "    </ProjectConfiguration>\n";

    ss << "  </ItemGroup>\n"
          "  <PropertyGroup Label=\"Globals\">\n"
          "    <ProjectGuid>{00000000-0000-0000-0000-000000000000}</ProjectGuid>\n"
          "    <RootNamespace>" << projectName << "</RootNamespace>\n"
          "    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\n"
          "  </PropertyGroup>\n"
          "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\n";

    for (auto& c : { std::string("Debug"), std::string("Release") })
    {
        bool dbg = (c == "Debug");
        ss << "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='"
           << c << "|" << arch << "'\" Label=\"Configuration\">\n"
              "    <ConfigurationType>DynamicLibrary</ConfigurationType>\n"
              "    <UseDebugLibraries>" << (dbg ? "true" : "false") << "</UseDebugLibraries>\n"
              "    <PlatformToolset>" << toolset << "</PlatformToolset>\n"
              "    <CharacterSet>MultiByte</CharacterSet>\n"
              "  </PropertyGroup>\n";
    }

    ss << "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\n";
    emitConfig("Debug");
    emitConfig("Release");

    ss << "  <ItemGroup>\n"
          "    <ClCompile Include=\"dllmain.cpp\" />\n"
          "  </ItemGroup>\n"
          "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\n"
          "</Project>\n";

    return ss.str();
}

// ────────────────────────────────────────────────────────────────────────────
// Process one DLL
// ────────────────────────────────────────────────────────────────────────────
static bool ProcessDll(const std::string& dllPath, const fs::path& outRoot)
{
    fs::path p(dllPath);
    if (!fs::exists(p))
    {
        std::cout << "[-] File not found: " << dllPath << "\n";
        return false;
    }

    std::string name = p.stem().string();
    std::string safe = Sanitize(name);

    auto exports = GetExports(dllPath);
    if (exports.empty())
    {
        std::cout << "[-] No exports parsed for: " << dllPath << "\n";
        return false;
    }

    std::string arch = GetArch(dllPath);

    size_t fwdCount = 0;
    for (auto& e : exports) if (e.isForwarder) ++fwdCount;

    std::cout << "[*] " << name
              << "  arch=" << arch
              << "  exports=" << exports.size()
              << "  forwarders=" << fwdCount << "\n";

    fs::path out = outRoot / safe;
    fs::create_directories(out);

    std::ofstream(out / "dllmain.cpp")       << GenCpp(name, exports);
    std::ofstream(out / (safe + ".def"))     << GenDef(name, exports);
    std::ofstream(out / (safe + ".vcxproj")) << GenVcxproj(safe, arch);
    std::ofstream(out / "README.md")
        << "# Stub DLL: " << name << "\n\n"
        << "- Architecture : " << arch << "\n"
        << "- Total exports: " << exports.size() << "\n"
        << "- Forwarders   : " << fwdCount << "\n\n"
        << "Logs load/unload to `C:\\temp\\test.txt`.\n\n"
        << "## Notes\n"
        << "- Forwarders are emitted as DEF forwarder entries; no stub body is generated.\n"
        << "- Ordinal-only exports are emitted as NONAME entries.\n"
        << "- Internal stub names (`stub_N`) are never used as public export names;\n"
        << "  the DEF file owns all public symbol identities.\n"
        << "- `WIN32_LEAN_AND_MEAN` is defined to minimize header collisions.\n";

    std::cout << "[+] Project -> " << out << "\n";
    return true;
}

// ────────────────────────────────────────────────────────────────────────────
// Main — one or more DLL paths
// ────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: stub_gen.exe <dll1> [dll2] [dll3] ...\n";
        return 1;
    }

    fs::path outRoot = fs::current_path();
    int ok = 0, fail = 0;

    for (int i = 1; i < argc; i++)
    {
        std::cout << "\n[===] Processing: " << argv[i] << "\n";
        if (ProcessDll(argv[i], outRoot)) ++ok; else ++fail;
    }

    std::cout << "\n[===] Done — " << ok << " succeeded, " << fail << " failed.\n";
    return (fail > 0) ? 1 : 0;
}
