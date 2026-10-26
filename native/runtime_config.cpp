#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <map>
#include <cstring>
#include "local_platform.h"
#include "offline_bootstrap.h"
#include "runtime_config.h"

namespace {
// Bundle-local public configuration. No launcher/account/cache lookup occurs.
bool LocalRoot(std::wstring& root) {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&LocalRoot), &module)) return false;
    wchar_t path[MAX_PATH]{};
    DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return false;
    std::wstring file(path);
    const std::wstring suffix = L"\\Base\\Bin\\uplay_r1_loader.dll";
    if (file.size() <= suffix.size() || _wcsicmp(file.c_str() + file.size() - suffix.size(), suffix.c_str()) != 0) return false;
    root = file.substr(0, file.size() - suffix.size()) + L"\\LocalData";
    return true;
}
bool ReadConfiguration(std::wstring& root, std::map<std::string, std::string>& fields) {
    if (!LocalRoot(root)) return false;
    std::wstring file = root + L"\\s7-local-runtime.ini";
    HANDLE input = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (input == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    FILETIME now_file{}; GetSystemTimeAsFileTime(&now_file);
    const auto ticks = [](FILETIME value) { return (static_cast<ULONGLONG>(value.dwHighDateTime) << 32) | value.dwLowDateTime; };
    bool valid = GetFileInformationByHandle(input, &info) && info.nFileSizeHigh == 0 && info.nFileSizeLow > 0 && info.nFileSizeLow < 2048
        && !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
    if (valid) valid = ticks(now_file) >= ticks(info.ftLastWriteTime)
        && ticks(now_file) - ticks(info.ftLastWriteTime) < 300ULL * 10000000;
    char bytes[2048]{}; DWORD received = 0;
    if (valid) valid = ReadFile(input, bytes, info.nFileSizeLow, &received, nullptr) && received == info.nFileSizeLow;
    CloseHandle(input);
    if (!valid) return false;
    std::string text(bytes, received);
    for (unsigned char c : text) if (c != '\n' && c != '\r' && (c < 32 || c > 126)) return false;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) return false;
        std::string line = text.substr(start, end - start); start = end + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t equals = line.find('=');
        if (equals == std::string::npos || equals == 0 || equals + 1 == line.size()) return false;
        if (!fields.emplace(line.substr(0, equals), line.substr(equals + 1)).second) return false;
    }
    bool valid_probe = fields.count("connect_probe") == 0 || fields.at("connect_probe") == "0" || fields.at("connect_probe") == "1";
    return valid_probe && fields.size() == 7 + fields.count("connect_probe") && fields["format"] == "s7-local-runtime-v1" && fields["address"] == "127.0.0.1"
        && fields.count("udp_port") && fields.count("public_key") && fields.count("profile_id")
        && fields.count("display_name") && fields.count("ticket");
}
}

void ReportLocalStatus(const char* label) {
    try {
        std::wstring root;
        size_t length = label ? strnlen_s(label, 256) : 0;
        if (!length || length == 256 || !LocalRoot(root)) return;
        HANDLE file = CreateFileW((root + L"\\native-status.txt").c_str(), FILE_APPEND_DATA,
            FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(file, &info) && !info.nFileSizeHigh && info.nFileSizeLow < 65536
            && !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            DWORD written = 0;
            WriteFile(file, label, static_cast<DWORD>(length), &written, nullptr);
            WriteFile(file, "\r\n", 2, &written, nullptr);
        }
        CloseHandle(file);
    } catch (...) { /* Diagnostics must never replace the failure being reported. */ }
}

bool InitializeOfflineBootstrap() {
    static bool initialized = false;
    if (initialized) return true;
    try {
        std::wstring root;
        std::map<std::string, std::string> fields;
        if (!ReadConfiguration(root, fields)) { ReportLocalStatus("runtime-configuration-unavailable"); return false; }
        const auto& port = fields.at("udp_port");
        if (port.empty() || port.size() > 5 || port[0] == '0') return false;
        unsigned value = 0;
        for (char c : port) { if (c < '0' || c > '9') return false; value = value * 10 + c - '0'; }
        if (!value || value > 65535 || fields.at("ticket") != "local-s7:" + fields.at("profile_id")
            || fields.at("display_name") != "LocalPlayer") return false;
        if (!InitializeLocalPlatform((root + L"\\saves").c_str(), fields.at("profile_id").c_str(),
            fields.at("display_name").c_str(), fields.at("ticket").c_str())) return false;
        OfflineBootstrapConfig config{static_cast<unsigned short>(value), fields.at("public_key").c_str(), fields.at("ticket").c_str()};
        config.local_connect_probe = fields.count("connect_probe") && fields.at("connect_probe") == "1";
        if (!InitializeOfflineBootstrap(config)) { ReportLocalStatus(GetOfflineBootstrapError()); return false; }
        initialized = true;
        ReportLocalStatus(config.local_connect_probe ? "native-bootstrap-installed-local-connect-probe" : "native-bootstrap-installed-login-trigger-unverified");
        return true;
    } catch (...) { return false; }
}
