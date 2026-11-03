#pragma once

#include <Windows.h>
#include <winioctl.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include "dump/shared/dump-protocol.h"

namespace win_obj::dump {
    struct Snapshot {
        Module module{};
        ULONGLONG started = 0;
        ULONGLONG finished = 0;
        std::vector<Page> pages;
        std::vector<unsigned char> image;
        bool Available(size_t offset, size_t count) const;
    };

    struct ImportSymbol {
        std::string name;
        WORD ordinal = 0;
        bool by_ordinal = false;
    };

    struct ImportEvidence {
        std::string module;
        ImportSymbol symbol;
        DWORD iat_rva = 0;
        ULONGLONG live_address = 0;
        bool recovered = false;
    };

    struct ExportSymbol {
        ImportSymbol symbol;
        ULONGLONG address = 0;
        std::string forwarder;
    };

    struct RebuiltImage {
        std::vector<unsigned char> bytes;
        std::vector<std::string> warnings;
        std::vector<ImportEvidence> imports;
        ULONGLONG preferred_base = 0;
        ULONGLONG output_base = 0;
        size_t relocations_reversed = 0;
    };

    using ImportResolver = std::function<std::optional<ImportSymbol>(const std::string&, ULONGLONG)>;
    // All input is memory-layout data. This module never opens an original image file.
    RebuiltImage RebuildImage(const Snapshot& snapshot, bool preferred_base, const ImportResolver& resolver);
    std::vector<ExportSymbol> ReadExports(const Snapshot& snapshot);
}
