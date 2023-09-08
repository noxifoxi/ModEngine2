#pragma once

#include <functional>
#include <algorithm>
#include <execution>
#include <optional>
#include <string>
#include <vector>
#include <exception>

#include <windows.h>
#include <MINT.h>
#include <mem/pattern.h>

namespace modengine {

struct ScanPattern {
    ScanPattern() : pattern() {}
    ScanPattern(const std::string &pattern) : pattern(pattern.c_str()) {}
    mem::pattern pattern;
};

class MemoryScanner {
public:
    MemoryScanner(HMODULE base) {
        uint64_t base64 = reinterpret_cast<uint64_t>(base);
        auto const section = IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(base64 + reinterpret_cast<PIMAGE_DOS_HEADER>(base64)->e_lfanew));
        mem_start = reinterpret_cast<uint8_t*>(base64 + section->VirtualAddress);
        mem_size = section->Misc.VirtualSize;
    }

    MemoryScanner() : MemoryScanner(GetModuleHandleW(nullptr)) {}

    std::optional<uintptr_t> find(const ScanPattern& pattern)
    {
        mem::simd_scanner scanner(pattern.pattern);
        std::optional<uintptr_t> result = std::nullopt;
        scanner({ mem_start, mem_size }, [&](mem::pointer res) {
            result = res.as<uintptr_t>();
            return false;
        });
        return result;
    }

    bool replace_at(uintptr_t location, std::function<void(uintptr_t)> replace_callback)
    {
        DWORD original_protection;

        if (!VirtualProtect((void*)location, 0x1000 /* PAGE_SIZE */, PAGE_EXECUTE_READWRITE, &original_protection)) {
            throw std::runtime_error("Unable to change process memory protection flags");
        }

        replace_callback(location);
        VirtualProtect((void*)location, 0x1000, original_protection, &original_protection);

        return true;
    }

    bool replace(const ScanPattern& pattern, std::function<void(uintptr_t)> replace_callback)
    {
        mem::simd_scanner scanner(pattern.pattern);
        std::optional<uintptr_t> result = std::nullopt;
        scanner({ mem_start, mem_size }, [&](mem::pointer res) {
            result = res.as<uintptr_t>();
            return false;
        });

        if (result.has_value()) {
            replace_callback(result.value());
            return true;
        }

        return false;
    }

private:
    const uint8_t *mem_start;
    size_t mem_size;
};

}
