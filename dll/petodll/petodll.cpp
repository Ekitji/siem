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
#include <cstring>

#pragma comment(lib, "winmm.lib")

namespace fs = std::filesystem;

struct ExportEntry
{
    std::string name;
    std::string forwardTarget;
    DWORD ordinal = 0;
    DWORD rva = 0;
    bool hasName = false;
    bool isForwarder = false;
    bool isData = false;
};

struct SectionInfo
{
    DWORD virtualAddress = 0;
    DWORD virtualSize = 0;
    DWORD rawSize = 0;
    DWORD rawPointer = 0;
    DWORD characteristics = 0;
};

struct PeMetadata
{
    WORD machine = 0;
    WORD magic = 0;
    DWORD exportRva = 0;
    DWORD exportSize = 0;
    DWORD sizeOfImage = 0;
    DWORD exportBase = 0;
    std::vector<SectionInfo> sections;
};

static std::string Sanitize(const std::string& s)
{
    std::string out;
    for (unsigned char c : s)
        out += (std::isalnum(c) || c == '_') ? static_cast<char>(c) : '_';
    if (out.empty()) out = "unnamed";
    if (std::isdigit(static_cast<unsigned char>(out[0]))) out = "_" + out;
    return out;
}

struct PEView
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = nullptr;
    LPBYTE base = nullptr;
    size_t size = 0;
    bool ok = false;

    explicit PEView(const std::string& path)
    {
        hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return;

        LARGE_INTEGER liSize{};
        if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0)
        {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return;
        }

        size = static_cast<size_t>(liSize.QuadPart);
        hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMap)
        {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return;
        }

        base = static_cast<LPBYTE>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!base)
        {
            CloseHandle(hMap);
            CloseHandle(hFile);
            hMap = nullptr;
            hFile = INVALID_HANDLE_VALUE;
            return;
        }

        ok = true;
    }

    ~PEView()
    {
        if (base) UnmapViewOfFile(base);
        if (hMap) CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }

    bool HasRange(size_t offset, size_t bytes) const
    {
        return offset <= size && bytes <= size - offset;
    }

    template <typename T>
    const T* PtrAt(size_t offset) const
    {
        if (!HasRange(offset, sizeof(T)))
            return nullptr;
        return reinterpret_cast<const T*>(base + offset);
    }

    bool ReadMetadata(PeMetadata& meta) const
    {
        if (!ok)
            return false;

        const auto* dos = PtrAt<IMAGE_DOS_HEADER>(0);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        const DWORD* signature = PtrAt<DWORD>(ntOffset);
        if (!signature || *signature != IMAGE_NT_SIGNATURE)
            return false;

        const auto* fileHeader = PtrAt<IMAGE_FILE_HEADER>(ntOffset + sizeof(DWORD));
        if (!fileHeader)
            return false;

        const auto* optMagic = PtrAt<WORD>(ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
        if (!optMagic)
            return false;

        meta = {};
        meta.machine = fileHeader->Machine;
        meta.magic = *optMagic;

        size_t sectionsOffset = 0;
        if (*optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            const auto* nt32 = PtrAt<IMAGE_NT_HEADERS32>(ntOffset);
            if (!nt32)
                return false;
            meta.exportRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            meta.exportSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            meta.sizeOfImage = nt32->OptionalHeader.SizeOfImage;
            sectionsOffset = ntOffset + sizeof(IMAGE_NT_HEADERS32);
        }
        else if (*optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            const auto* nt64 = PtrAt<IMAGE_NT_HEADERS64>(ntOffset);
            if (!nt64)
                return false;
            meta.exportRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            meta.exportSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            meta.sizeOfImage = nt64->OptionalHeader.SizeOfImage;
            sectionsOffset = ntOffset + sizeof(IMAGE_NT_HEADERS64);
        }
        else
        {
            return false;
        }

        meta.sections.reserve(fileHeader->NumberOfSections);
        for (WORD i = 0; i < fileHeader->NumberOfSections; ++i)
        {
            const auto* sec = PtrAt<IMAGE_SECTION_HEADER>(sectionsOffset + i * sizeof(IMAGE_SECTION_HEADER));
            if (!sec)
                return false;

            SectionInfo info;
            info.virtualAddress = sec->VirtualAddress;
            info.virtualSize = sec->Misc.VirtualSize;
            info.rawSize = sec->SizeOfRawData;
            info.rawPointer = sec->PointerToRawData;
            info.characteristics = sec->Characteristics;
            meta.sections.push_back(info);
        }

        return true;
    }

    DWORD RvaToOffset(DWORD rva, const PeMetadata& meta) const
    {
        for (const auto& sec : meta.sections)
        {
            const DWORD mappedSize = (std::max)(sec.virtualSize, sec.rawSize);
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + mappedSize)
                return sec.rawPointer + (rva - sec.virtualAddress);
        }

        if (rva < size)
            return rva;
        return 0;
    }

    const SectionInfo* FindSection(DWORD rva, const PeMetadata& meta) const
    {
        for (const auto& sec : meta.sections)
        {
            const DWORD mappedSize = (std::max)(sec.virtualSize, sec.rawSize);
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + mappedSize)
                return &sec;
        }
        return nullptr;
    }
};

static bool IsLikelyDataExport(DWORD rva, const PEView& view, const PeMetadata& meta)
{
    const SectionInfo* sec = view.FindSection(rva, meta);
    if (!sec)
        return false;

    if ((sec->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        return false;

    if ((sec->characteristics & IMAGE_SCN_MEM_READ) != 0)
        return true;

    return false;
}

static std::vector<ExportEntry> GetExports(const std::string& path, PeMetadata& meta)
{
    std::vector<ExportEntry> exports;
    PEView view(path);
    if (!view.ok)
    {
        std::cout << "[-] Cannot open: " << path << "\n";
        return exports;
    }

    if (!view.ReadMetadata(meta))
    {
        std::cout << "[-] Bad PE headers: " << path << "\n";
        return exports;
    }

    if (meta.exportRva == 0 || meta.exportSize == 0)
    {
        std::cout << "[!] No export directory: " << path << "\n";
        return exports;
    }

    const DWORD exportOff = view.RvaToOffset(meta.exportRva, meta);
    if (!exportOff)
    {
        std::cout << "[-] Export dir RVA not mapped\n";
        return exports;
    }

    const auto* ed = view.PtrAt<IMAGE_EXPORT_DIRECTORY>(exportOff);
    if (!ed)
    {
        std::cout << "[-] Export dir truncated\n";
        return exports;
    }

    if (ed->NumberOfFunctions == 0)
    {
        std::cout << "[!] Zero functions exported\n";
        return exports;
    }

    meta.exportBase = ed->Base;

    const DWORD funcOff = view.RvaToOffset(ed->AddressOfFunctions, meta);
    if (!funcOff || !view.HasRange(funcOff, static_cast<size_t>(ed->NumberOfFunctions) * sizeof(DWORD)))
    {
        std::cout << "[-] Function table invalid\n";
        return exports;
    }

    const auto* funcRVAs = reinterpret_cast<const DWORD*>(view.base + funcOff);

    const DWORD* nameRVAs = nullptr;
    const WORD* nameOrdinals = nullptr;
    if (ed->NumberOfNames > 0)
    {
        const DWORD namesOff = view.RvaToOffset(ed->AddressOfNames, meta);
        const DWORD ordsOff = view.RvaToOffset(ed->AddressOfNameOrdinals, meta);
        if (namesOff && ordsOff &&
            view.HasRange(namesOff, static_cast<size_t>(ed->NumberOfNames) * sizeof(DWORD)) &&
            view.HasRange(ordsOff, static_cast<size_t>(ed->NumberOfNames) * sizeof(WORD)))
        {
            nameRVAs = reinterpret_cast<const DWORD*>(view.base + namesOff);
            nameOrdinals = reinterpret_cast<const WORD*>(view.base + ordsOff);
        }
    }

    std::vector<std::string> nameByIndex(ed->NumberOfFunctions);
    std::vector<bool> hasNameByIndex(ed->NumberOfFunctions, false);
    if (nameRVAs && nameOrdinals)
    {
        for (DWORD i = 0; i < ed->NumberOfNames; ++i)
        {
            const WORD index = nameOrdinals[i];
            if (index >= ed->NumberOfFunctions)
                continue;

            const DWORD nameOff = view.RvaToOffset(nameRVAs[i], meta);
            if (!nameOff || !view.HasRange(nameOff, 1))
                continue;

            nameByIndex[index] = reinterpret_cast<const char*>(view.base + nameOff);
            hasNameByIndex[index] = true;
        }
    }

    const DWORD exportDirStart = meta.exportRva;
    const DWORD exportDirEnd = meta.exportRva + meta.exportSize;

    exports.reserve(ed->NumberOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfFunctions; ++i)
    {
        const DWORD rva = funcRVAs[i];
        if (rva == 0)
            continue;

        ExportEntry entry;
        entry.ordinal = ed->Base + i;
        entry.rva = rva;
        entry.hasName = hasNameByIndex[i];
        if (entry.hasName)
            entry.name = nameByIndex[i];

        if (rva >= exportDirStart && rva < exportDirEnd)
        {
            entry.isForwarder = true;
            const DWORD forwardOff = view.RvaToOffset(rva, meta);
            if (forwardOff && view.HasRange(forwardOff, 1))
                entry.forwardTarget = reinterpret_cast<const char*>(view.base + forwardOff);
        }
        else
        {
            entry.isData = IsLikelyDataExport(rva, view, meta);
        }

        exports.push_back(entry);
    }

    std::cout << "[+] " << path << " — " << exports.size() << " exports\n";
    return exports;
}

static std::string GetPlatformName(const PeMetadata& meta)
{
    switch (meta.machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        return "Win32";
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
        return "ARM64";
    default:
        return "Win32";
    }
}

static std::string DecoratedStubName(size_t index, const std::string& arch, bool isData)
{
    (void)isData;
    const std::string base = "stub_" + std::to_string(index);
    if (arch == "Win32")
        return "_" + base;
    return base;
}

static std::string GenCpp(const std::string& dllName, const std::vector<ExportEntry>& exports)
{
    std::stringstream ss;

    ss << "#define NOMINMAX\n"
        "#define WIN32_LEAN_AND_MEAN\n"
        "#include <windows.h>\n"
        "#include <mmsystem.h>\n"
        "#pragma comment(lib, \"winmm.lib\")\n\n";

    ss << "static const char* g_DllName = \"" << dllName << "\";\n\n";

    ss << R"(static void AppendLogLine(const char* line)
{
    CreateDirectoryA("C:\\temp", NULL);
    HANDLE h = CreateFileA("C:\\temp\\test.txt", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;

    DWORD written = 0;
    WriteFile(h, line, (DWORD)lstrlenA(line), &written, NULL);
    CloseHandle(h);
}

static void Log(HMODULE hModule, const char* msg)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    char user[256] = "UNKNOWN";
    DWORD userSize = sizeof(user);
    GetUserNameA(user, &userSize);

    char exePath[MAX_PATH] = "UNKNOWN";
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char dllPath[MAX_PATH] = "UNKNOWN";
    GetModuleFileNameA(hModule, dllPath, MAX_PATH);

    char line[2048];
    wsprintfA(line,
        "[%04u-%02u-%02u %02u:%02u:%02u] DLL: %s | %s | User: %s | EXE: %s | DLL: %s\r\n",
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        g_DllName, msg ? msg : "?", user, exePath, dllPath);

    AppendLogLine(line);
}

static DWORD WINAPI PlayRing05Thread(LPVOID)
{
    Sleep(500);
    PlaySoundA("C:\\Windows\\Media\\Ring05.wav", NULL, SND_FILENAME | SND_ASYNC);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Log(hModule, "Loaded");
        HANDLE hThread = CreateThread(NULL, 0, PlayRing05Thread, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        Log(hModule, "Unloaded");
    }
    return TRUE;
}

)";

    ss << "// Internal stubs are intentionally plain and minimal.\n";
    for (size_t i = 0; i < exports.size(); ++i)
    {
        const auto& e = exports[i];
        if (e.isForwarder)
            continue;

        if (e.isData)
            ss << "extern \"C\" __declspec(selectany) unsigned char stub_" << i << " = 0;\n";
        else
            ss << "extern \"C\" void __cdecl stub_" << i << "() {}\n";
    }

    return ss.str();
}

static std::string MakeOrdinalForwarderAlias(DWORD ordinal)
{
    return "__ord_fwd_" + std::to_string(ordinal);
}

static std::string GenDef(const std::string& dllName,
    const std::string& arch,
    const std::vector<ExportEntry>& exports)
{
    std::stringstream ss;
    ss << "LIBRARY " << dllName << "\n";
    ss << "EXPORTS\n";

    for (size_t i = 0; i < exports.size(); ++i)
    {
        const auto& e = exports[i];
        const std::string dataSuffix = e.isData ? " DATA" : "";

        if (e.isForwarder)
        {
            if (e.forwardTarget.empty())
                continue;

            if (e.hasName)
            {
                ss << "    " << e.name << "=" << e.forwardTarget << " @" << e.ordinal << "\n";
            }
            else
            {
                ss << "    " << MakeOrdinalForwarderAlias(e.ordinal) << "=" << e.forwardTarget
                    << " @" << e.ordinal << " NONAME\n";
            }
            continue;
        }

        const std::string internal = DecoratedStubName(i, arch, e.isData);
        if (e.hasName)
        {
            ss << "    " << e.name << "=" << internal << " @" << e.ordinal << dataSuffix << "\n";
        }
        else
        {
            ss << "    " << internal << " @" << e.ordinal << " NONAME" << dataSuffix << "\n";
        }
    }

    return ss.str();
}

static std::string GenVcxproj(const std::string& projectName, const std::string& arch)
{
    std::stringstream ss;

    auto emitConfig = [&](const std::string& config)
        {
            const bool debug = (config == "Debug");
            ss << "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='"
                << config << "|" << arch << "'\">\n"
                "    <ClCompile>\n"
                "      <WarningLevel>Level3</WarningLevel>\n"
                "      <SDLCheck>true</SDLCheck>\n"
                "      <PreprocessorDefinitions>"
                << (debug ? "_DEBUG" : "NDEBUG")
                << ";_WINDOWS;_USRDLL;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n"
                "      <Optimization>" << (debug ? "Disabled" : "MaxSpeed") << "</Optimization>\n"
                "      <RuntimeLibrary>" << (debug ? "MultiThreadedDebug" : "MultiThreaded") << "</RuntimeLibrary>\n"
                "    </ClCompile>\n"
                "    <Link>\n"
                "      <SubSystem>Windows</SubSystem>\n"
                "      <GenerateDebugInformation>true</GenerateDebugInformation>\n"
                "      <AdditionalDependencies>winmm.lib;%(AdditionalDependencies)</AdditionalDependencies>\n"
                "      <ModuleDefinitionFile>" << projectName << ".def</ModuleDefinitionFile>\n"
                "    </Link>\n"
                "  </ItemDefinitionGroup>\n";
        };

    ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
        "  <ItemGroup Label=\"ProjectConfigurations\">\n";

    for (const auto& config : { std::string("Debug"), std::string("Release") })
    {
        ss << "    <ProjectConfiguration Include=\"" << config << "|" << arch << "\">\n"
            "      <Configuration>" << config << "</Configuration>\n"
            "      <Platform>" << arch << "</Platform>\n"
            "    </ProjectConfiguration>\n";
    }

    ss << "  </ItemGroup>\n"
        "  <PropertyGroup Label=\"Globals\">\n"
        "    <ProjectGuid>{00000000-0000-0000-0000-000000000000}</ProjectGuid>\n"
        "    <RootNamespace>" << projectName << "</RootNamespace>\n"
        "    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\n"
        "  </PropertyGroup>\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\n";

    for (const auto& config : { std::string("Debug"), std::string("Release") })
    {
        const bool debug = (config == "Debug");
        ss << "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='"
            << config << "|" << arch << "'\" Label=\"Configuration\">\n"
            "    <ConfigurationType>DynamicLibrary</ConfigurationType>\n"
            "    <UseDebugLibraries>" << (debug ? "true" : "false") << "</UseDebugLibraries>\n"
            "    <CharacterSet>MultiByte</CharacterSet>\n"
            "  </PropertyGroup>\n";
    }

    ss << "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\n"
        "  <ImportGroup Label=\"ExtensionSettings\" />\n"
        "  <ImportGroup Label=\"Shared\" />\n";

    for (const auto& config : { std::string("Debug"), std::string("Release") })
    {
        ss << "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='"
            << config << "|" << arch << "'\">\n"
            "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" "
            "Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\" "
            "Label=\"LocalAppDataPlatform\" />\n"
            "  </ImportGroup>\n";
    }

    ss << "  <PropertyGroup Label=\"UserMacros\" />\n";
    emitConfig("Debug");
    emitConfig("Release");
    ss << "  <ItemGroup>\n"
        "    <ClCompile Include=\"dllmain.cpp\" />\n"
        "  </ItemGroup>\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\n"
        "  <ImportGroup Label=\"ExtensionTargets\" />\n"
        "</Project>\n";

    return ss.str();
}

static bool ProcessDll(const std::string& dllPath, const fs::path& outRoot)
{
    const fs::path path(dllPath);
    if (!fs::exists(path))
    {
        std::cout << "[-] File not found: " << dllPath << "\n";
        return false;
    }

    const std::string name = path.stem().string();
    const std::string safeName = Sanitize(name);

    PeMetadata meta;
    const auto exports = GetExports(dllPath, meta);
    if (exports.empty())
    {
        std::cout << "[-] No exports parsed for: " << dllPath << "\n";
        return false;
    }

    const std::string arch = GetPlatformName(meta);

    size_t forwarderCount = 0;
    size_t dataCount = 0;
    for (const auto& e : exports)
    {
        if (e.isForwarder) ++forwarderCount;
        if (e.isData) ++dataCount;
    }

    std::cout << "[*] " << name
        << "  arch=" << arch
        << "  exports=" << exports.size()
        << "  forwarders=" << forwarderCount
        << "  data=" << dataCount << "\n";

    const fs::path outDir = outRoot / safeName;
    fs::create_directories(outDir);

    std::ofstream(outDir / "dllmain.cpp") << GenCpp(name, exports);
    std::ofstream(outDir / (safeName + ".def")) << GenDef(name, arch, exports);
    std::ofstream(outDir / (safeName + ".vcxproj")) << GenVcxproj(safeName, arch);
    std::ofstream(outDir / "README.md")
        << "# Stub DLL: " << name << "\n\n"
        << "- Architecture : " << arch << "\n"
        << "- Total exports: " << exports.size() << "\n"
        << "- Forwarders   : " << forwarderCount << "\n"
        << "- Data exports : " << dataCount << "\n\n"
        << "Logs load/unload to `C:\\temp\\test.txt` and plays `C:\\Windows\\Media\\Ring05.wav` on load.\n\n"
        << "## Notes\n"
        << "- PE32, PE32+, and ARM64 image headers are parsed explicitly.\n"
        << "- Win32 stub aliases use decorated internal names where needed for linker compatibility.\n"
        << "- Forwarders are emitted through the DEF file, including ordinal-only forwarders.\n"
        << "- Exports mapped to non-executable sections are marked as `DATA` heuristically.\n"
        << "- Internal stub names are implementation details; the DEF file owns the public export surface.\n";

    std::cout << "[+] Project -> " << outDir << "\n";
    return true;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: stub_gen.exe <dll1> [dll2] [dll3] ...\n";
        return 1;
    }

    const fs::path outRoot = fs::current_path();
    int ok = 0;
    int fail = 0;

    for (int i = 1; i < argc; ++i)
    {
        std::cout << "\n[===] Processing: " << argv[i] << "\n";
        if (ProcessDll(argv[i], outRoot))
            ++ok;
        else
            ++fail;
    }

    std::cout << "\n[===] Done - " << ok << " succeeded, " << fail << " failed.\n";
    return fail > 0 ? 1 : 0;
}
