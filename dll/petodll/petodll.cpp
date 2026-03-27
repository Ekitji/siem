#include <windows.h>
#include <mmsystem.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#pragma comment(lib, "winmm.lib")

namespace fs = std::filesystem;

// ── Helper: sanitize function names
std::string Sanitize(const std::string& s)
{
    std::string out;
    for (char c : s)
        out += (isalnum(c) || c == '_') ? c : '_';
    return out;
}

// ── Parse exports safely
std::vector<std::string> GetExports(const std::string& path)
{
    std::vector<std::string> exports;

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { std::cout << "[-] Failed to open file\n"; return exports; }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { std::cout << "[-] Failed to create file mapping\n"; CloseHandle(hFile); return exports; }

    LPBYTE base = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { std::cout << "[-] Failed to map view of file\n"; CloseHandle(hMap); CloseHandle(hFile); return exports; }

    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { std::cout << "[-] Invalid DOS header\n"; UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return exports; }

    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { std::cout << "[-] Invalid NT header\n"; UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return exports; }

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) { std::cout << "[!] No export directory\n"; UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return exports; }

    auto sections = IMAGE_FIRST_SECTION(nt);
    auto RvaToOffset = [&](DWORD rva) -> DWORD {
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            DWORD start = sections[i].VirtualAddress;
            DWORD end = start + sections[i].Misc.VirtualSize;
            if (rva >= start && rva < end) return sections[i].PointerToRawData + (rva - start);
        }
        return rva;
        };

    DWORD exportOffset = RvaToOffset(dir.VirtualAddress);
    auto exportDir = (IMAGE_EXPORT_DIRECTORY*)(base + exportOffset);

    if (exportDir->NumberOfFunctions == 0) { std::cout << "[!] No functions\n"; UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return exports; }

    DWORD* functions = (DWORD*)(base + RvaToOffset(exportDir->AddressOfFunctions));
    DWORD* nameRVAs = (exportDir->NumberOfNames > 0) ? (DWORD*)(base + RvaToOffset(exportDir->AddressOfNames)) : nullptr;
    WORD* ordinals = (exportDir->NumberOfNames > 0) ? (WORD*)(base + RvaToOffset(exportDir->AddressOfNameOrdinals)) : nullptr;

    for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++)
    {
        std::string expName;
        bool hasName = false;

        if (nameRVAs && ordinals)
        {
            for (DWORD j = 0; j < exportDir->NumberOfNames; j++)
            {
                if (ordinals[j] == i)
                {
                    DWORD noff = RvaToOffset(nameRVAs[j]);
                    expName = (char*)(base + noff);
                    hasName = true;
                    break;
                }
            }
        }

        if (!hasName) expName = "Ordinal_" + std::to_string(exportDir->Base + i);

        exports.push_back(expName);
    }

    std::cout << "[+] Parsed " << exports.size() << " exports\n";

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return exports;
}

// ── Determine architecture
std::string GetArch(const std::string& path)
{
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPBYTE base = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    std::string arch = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? "x64" : "Win32";
    UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile);
    return arch;
}

// ── Detect installed toolset (simplified)
std::string DetectToolset()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Tools\\MSVC", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char name[256]; DWORD size = sizeof(name);
        if (RegEnumKeyExA(hKey, 0, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return "v143";
        }
        RegCloseKey(hKey);
    }
    return "v142";
}

// ── Generate dllmain.cpp
std::string GenCpp(const std::string& dllName, const std::vector<std::string>& exports)
{
    std::stringstream ss;
    ss << "#include <windows.h>\n#include <stdio.h>\n#include <mmsystem.h>\n#pragma comment(lib, \"winmm.lib\")\n\n";

    // Log function
    ss << R"(static void Log(HMODULE hModule, const char* msg){
    CreateDirectoryA("C:\\temp", NULL);
    FILE* f;
    fopen_s(&f, "C:\\temp\\test.txt", "a");
    if(f){
        SYSTEMTIME st;
        GetLocalTime(&st);

        char user[256];
        DWORD size = sizeof(user);
        if(!GetUserNameA(user, &size)) strcpy_s(user, "UNKNOWN");

        char exePath[MAX_PATH];
        if(!GetModuleFileNameA(NULL, exePath, MAX_PATH)) strcpy_s(exePath, "UNKNOWN");

        char dllPath[MAX_PATH];
        if(!GetModuleFileNameA(hModule, dllPath, MAX_PATH)) strcpy_s(dllPath, "UNKNOWN");

        fprintf(f, "[%02d:%02d:%02d] DLL: )" << dllName << R"( | %s | User: %s | EXE: %s | DLL: %s\n",
            st.wHour, st.wMinute, st.wSecond, msg, user, exePath, dllPath);
        fclose(f);
    }
})" << "\n\n";

    // Sound thread - same pattern as a standalone EXE test, with failure logging
    ss << R"(DWORD WINAPI PlayRing05Thread(LPVOID){
    Sleep(500);
    if(!PlaySoundA("C:\\Windows\\Media\\Ring05.wav", NULL, SND_FILENAME | SND_SYNC)){
        CreateDirectoryA("C:\\temp", NULL);
        FILE* f;
        fopen_s(&f, "C:\\temp\\test.txt", "a");
        if(f){ fprintf(f, "PlaySoundA failed - GetLastError: %lu\n", GetLastError()); fclose(f); }
    }
    return 0;
})" << "\n\n";

    // DllMain
    ss << R"(BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID){
    if(reason == DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(hModule);
        Log(hModule, "Loaded");
        CreateThread(NULL, 0, PlayRing05Thread, NULL, 0, NULL);
    } else if(reason == DLL_PROCESS_DETACH){
        Log(hModule, "Unloaded");
    }
    return TRUE;
})" << "\n\n";

    // Export stubs
    for (auto& e : exports)
        ss << "extern \"C\" __declspec(dllexport) void " << Sanitize(e) << "() {}\n";

    return ss.str();
}

// ── Generate DEF file
std::string GenDef(const std::string& name, const std::vector<std::string>& exports)
{
    std::stringstream ss;
    ss << "LIBRARY " << name << "\nEXPORTS\n";
    for (auto& e : exports) ss << "    " << e << "\n";
    return ss.str();
}

// ── Generate VCXPROJ
std::string GenVcxproj(const std::string& projectName, const std::string& arch)
{
    std::string toolset = DetectToolset();
    std::stringstream ss;
    ss << R"(<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|)" << arch << R"("><Configuration>Debug</Configuration><Platform>)" << arch << R"(</Platform></ProjectConfiguration>
    <ProjectConfiguration Include="Release|)" << arch << R"("><Configuration>Release</Configuration><Platform>)" << arch << R"(</Platform></ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{00000000-0000-0000-0000-000000000000}</ProjectGuid>
    <RootNamespace>)" << projectName << R"(</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
    <Keyword>Win32Proj</Keyword>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|)" << arch << R"('" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>)" << toolset << R"(</PlatformToolset>
    <CharacterSet>MultiByte</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|)" << arch << R"('" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>)" << toolset << R"(</PlatformToolset>
    <CharacterSet>MultiByte</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|)" << arch << R"('">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <PreprocessorDefinitions>_DEBUG;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <AdditionalDependencies>winmm.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|)" << arch << R"('">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <PreprocessorDefinitions>NDEBUG;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <AdditionalDependencies>winmm.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup><ClCompile Include="dllmain.cpp"/></ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>)";
    return ss.str();
}

// ── Main
int main(int argc, char* argv[])
{
    if (argc < 2) { std::cout << "Usage: tool.exe <dll>\n"; return 1; }

    std::string dllPath = argv[1];
    fs::path p(dllPath);
    if (!fs::exists(p)) { std::cout << "[-] File not found: " << dllPath << "\n"; return 1; }

    std::string name = p.stem().string();
    std::string safe = Sanitize(name);

    std::cout << "[*] Parsing DLL: " << dllPath << "\n";
    auto exports = GetExports(dllPath);
    if (exports.empty()) { std::cout << "[-] No exports parsed.\n"; return 1; }

    std::string arch = GetArch(dllPath);
    std::cout << "[*] DLL: " << name << "  Exports: " << exports.size() << "  Arch: " << arch << "\n";

    fs::path out = fs::current_path() / safe;
    fs::create_directories(out);

    std::ofstream(out / "dllmain.cpp") << GenCpp(name, exports);
    std::ofstream(out / (safe + ".def")) << GenDef(name, exports);
    std::ofstream(out / (safe + ".vcxproj")) << GenVcxproj(safe, arch);
    std::ofstream(out / "README.md") << "Stub DLL for " + name + "\nLogs load/unload to C:\\temp\\test.txt, including executable path, DLL path, and user. Plays Ring05.wav on load.\n";

    std::cout << "[+] Stub project created at: " << out << "\n";
}