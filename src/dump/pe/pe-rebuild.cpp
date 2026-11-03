#include "dump/pe/pe-rebuild.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {
    using namespace win_obj::dump;
    [[noreturn]] void Fail(const char* text) { throw std::runtime_error(text); }
    bool Range(size_t offset, size_t count, size_t size) { return offset <= size && count <= size - offset; }
    DWORD Align(DWORD value, DWORD alignment) {
        if (!alignment || (alignment & (alignment - 1)) || value > MAXDWORD - alignment + 1)
            Fail("Invalid PE alignment or size overflow.");
        return (value + alignment - 1) & ~(alignment - 1);
    }
    template<class T> T Read(const Snapshot& image, size_t offset) {
        if (!image.Available(offset, sizeof(T))) Fail("Required PE structure is missing or outside the captured image.");
        T result;
        memcpy(&result, image.image.data() + offset, sizeof(result));
        return result;
    }
    template<class T> void Write(std::vector<unsigned char>& image, size_t offset, const T& value) {
        if (!Range(offset, sizeof(T), image.size())) Fail("PE output offset overflow.");
        memcpy(image.data() + offset, &value, sizeof(value));
    }
    std::string String(const Snapshot& image, size_t offset) {
        std::string result;
        for (size_t i = 0; i < 4096; ++i) {
            auto c = Read<char>(image, offset + i);
            if (!c) return result;
            result.push_back(c);
        }
        Fail("Unterminated or oversized PE string.");
    }

    struct Pe {
        const Snapshot& source;
        DWORD nt = 0;
        DWORD optional = 0;
        DWORD section_table = 0;
        IMAGE_FILE_HEADER file{};
        IMAGE_OPTIONAL_HEADER64 header{};
        std::vector<IMAGE_SECTION_HEADER> sections;

        explicit Pe(const Snapshot& image) : source(image) {
            if (image.image.size() != image.module.size || image.image.empty() || image.image.size() > max_image_size)
                Fail("Invalid captured image size.");
            auto dos = Read<IMAGE_DOS_HEADER>(image, 0);
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos)) Fail("Missing DOS/PE header in memory.");
            nt = dos.e_lfanew;
            if (nt > image.image.size() || Read<DWORD>(image, nt) != IMAGE_NT_SIGNATURE) Fail("Invalid PE signature.");
            file = Read<IMAGE_FILE_HEADER>(image, nt + sizeof(DWORD));
            if (file.Machine != IMAGE_FILE_MACHINE_AMD64 || !file.NumberOfSections || file.NumberOfSections > 95 ||
                file.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) Fail("Only AMD64 PE32+ images with valid section tables are supported.");
            optional = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
            header = Read<IMAGE_OPTIONAL_HEADER64>(image, optional);
            if (header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || header.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
                header.SizeOfImage != image.module.size || header.FileAlignment < 512 || header.FileAlignment > 65536 ||
                header.SectionAlignment < header.FileAlignment || header.SectionAlignment < page_size ||
                header.SizeOfHeaders > image.image.size()) Fail("Unsupported or inconsistent PE optional header.");
            Align(0, header.FileAlignment);
            Align(0, header.SectionAlignment);
            section_table = optional + file.SizeOfOptionalHeader;
            if (section_table > header.SizeOfHeaders || file.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > header.SizeOfHeaders - section_table)
                Fail("Section table exceeds PE headers.");
            if (!image.Available(0, header.SizeOfHeaders)) Fail("PE headers are partially unreadable.");
            for (DWORD i = 0; i < file.NumberOfSections; ++i) {
                auto section = Read<IMAGE_SECTION_HEADER>(image, section_table + i * sizeof(IMAGE_SECTION_HEADER));
                auto size = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
                if (section.VirtualAddress < header.SizeOfHeaders || section.VirtualAddress % header.SectionAlignment ||
                    !Range(section.VirtualAddress, size, image.image.size())) Fail("Invalid mapped section range.");
                for (const auto& other : sections) {
                    auto other_size = (std::max)(other.Misc.VirtualSize, other.SizeOfRawData);
                    if (size && other_size && section.VirtualAddress < other.VirtualAddress + other_size &&
                        other.VirtualAddress < section.VirtualAddress + size) Fail("Overlapping mapped PE sections.");
                }
                sections.push_back(section);
            }
        }

        IMAGE_DATA_DIRECTORY Directory(size_t index) const {
            return index < header.NumberOfRvaAndSizes ? header.DataDirectory[index] : IMAGE_DATA_DIRECTORY{};
        }
        bool Mapped(DWORD rva, size_t bytes) const {
            for (const auto& s : sections) {
                auto size = (std::max)(s.Misc.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && Range(rva - s.VirtualAddress, bytes, size)) return true;
            }
            return false;
        }
    };

    struct ImportGroup {
        std::string module;
        DWORD first_thunk = 0;
        std::vector<ImportEvidence> entries;
    };

    std::vector<ImportGroup> Imports(const Pe& pe, const ImportResolver& resolver) {
        auto directory = pe.Directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!directory.VirtualAddress && !directory.Size) {
            if (pe.Directory(IMAGE_DIRECTORY_ENTRY_IAT).Size) Fail("IAT exists but import descriptors are missing; cannot infer DLL boundaries safely.");
            return {};
        }
        if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !pe.Mapped(directory.VirtualAddress, directory.Size)) Fail("Invalid import directory.");
        std::vector<ImportGroup> groups;
        size_t total = 0;
        for (size_t i = 0; i < directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) && i < 4096; ++i) {
            auto desc = Read<IMAGE_IMPORT_DESCRIPTOR>(pe.source, directory.VirtualAddress + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!desc.Name && !desc.FirstThunk && !desc.OriginalFirstThunk && !desc.TimeDateStamp && !desc.ForwarderChain) return groups;
            if (!desc.Name || !desc.FirstThunk) Fail("Incomplete import descriptor.");
            ImportGroup group{ String(pe.source, desc.Name), desc.FirstThunk };
            if (group.module.empty()) Fail("Empty import module name.");
            bool terminated = false;
            for (size_t j = 0; total < 65536; ++j, ++total) {
                auto offset = static_cast<size_t>(desc.FirstThunk) + j * sizeof(ULONGLONG);
                if (offset > MAXDWORD || !pe.Mapped(static_cast<DWORD>(offset), sizeof(ULONGLONG))) Fail("IAT exceeds a mapped section.");
                auto live = Read<ULONGLONG>(pe.source, offset);
                if (!live) { terminated = true; break; }
                ImportEvidence entry{ group.module, {}, static_cast<DWORD>(offset), live };
                bool found = false;
                if (desc.OriginalFirstThunk && desc.OriginalFirstThunk != desc.FirstThunk) {
                    try {
                        auto value = Read<ULONGLONG>(pe.source, static_cast<size_t>(desc.OriginalFirstThunk) + j * sizeof(ULONGLONG));
                        if ((value & IMAGE_ORDINAL_FLAG64) && !(value & ~(IMAGE_ORDINAL_FLAG64 | 0xffffull))) {
                            entry.symbol.by_ordinal = true;
                            entry.symbol.ordinal = static_cast<WORD>(value);
                            found = true;
                        }
                        else if (value && value <= MAXDWORD) {
                            Read<WORD>(pe.source, static_cast<size_t>(value));
                            entry.symbol.name = String(pe.source, static_cast<size_t>(value) + sizeof(WORD));
                            found = !entry.symbol.name.empty();
                        }
                    }
                    catch (const std::runtime_error&) { /* Recover from the live IAT below. */ }
                }
                if (!found) {
                    auto symbol = resolver ? resolver(group.module, live) : std::nullopt;
                    if (!symbol) Fail("An import name cannot be recovered from memory; raw capture remains authoritative.");
                    entry.symbol = *symbol;
                    entry.recovered = true;
                }
                group.entries.push_back(std::move(entry));
            }
            if (!terminated) Fail("Import count limit exceeded or unterminated IAT.");
            for (const auto& previous : groups) {
                auto end = static_cast<size_t>(group.first_thunk) + (group.entries.size() + 1) * 8;
                auto previous_end = static_cast<size_t>(previous.first_thunk) + (previous.entries.size() + 1) * 8;
                if (group.first_thunk < previous_end && previous.first_thunk < end) Fail("Overlapping import address tables.");
            }
            groups.push_back(std::move(group));
        }
        Fail("Import descriptor terminator is missing.");
    }

    void Relocations(const Pe& pe, std::vector<unsigned char>& mapped, bool preferred, RebuiltImage& result,
        IMAGE_OPTIONAL_HEADER64& header) {
        auto directory = pe.Directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        auto delta = pe.source.module.base - pe.header.ImageBase;
        bool available = directory.VirtualAddress && directory.Size &&
            pe.Mapped(directory.VirtualAddress, directory.Size) && pe.source.Available(directory.VirtualAddress, directory.Size);
        if (!available) {
            if (preferred && delta) Fail("Preferred-base reconstruction needs a complete in-memory relocation directory. Use --base loaded.");
            header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {};
            header.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            if (directory.Size) result.warnings.push_back("Relocation data was unavailable; output is fixed at its recorded image base.");
            return;
        }
        size_t used = 0;
        std::vector<std::pair<DWORD, WORD>> entries;
        while (used < directory.Size) {
            if (directory.Size - used < sizeof(IMAGE_BASE_RELOCATION)) Fail("Truncated relocation block.");
            auto block = Read<IMAGE_BASE_RELOCATION>(pe.source, directory.VirtualAddress + used);
            if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > directory.Size - used || block.SizeOfBlock % 2)
                Fail("Malformed relocation block.");
            for (size_t n = sizeof(block); n < block.SizeOfBlock; n += sizeof(WORD)) {
                auto item = Read<WORD>(pe.source, directory.VirtualAddress + used + n);
                auto type = static_cast<WORD>(item >> 12);
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                if (type != IMAGE_REL_BASED_DIR64 && type != IMAGE_REL_BASED_HIGHLOW) Fail("Unsupported AMD64 relocation type.");
                if (block.VirtualAddress > MAXDWORD - (item & 0xfff)) Fail("Relocation RVA overflow.");
                auto rva = block.VirtualAddress + (item & 0xfff);
                auto width = type == IMAGE_REL_BASED_DIR64 ? 8u : 4u;
                if (!pe.Mapped(rva, width)) Fail("Relocation target is outside mapped sections.");
                entries.push_back({ rva, type });
            }
            used += block.SizeOfBlock;
        }
        std::sort(entries.begin(), entries.end());
        for (size_t i = 1; i < entries.size(); ++i)
            if (entries[i].first < entries[i - 1].first + (entries[i - 1].second == IMAGE_REL_BASED_DIR64 ? 8u : 4u))
                Fail("Overlapping relocation targets.");
        if (preferred && delta) {
            for (const auto& [rva, type] : entries) {
                if (type == IMAGE_REL_BASED_DIR64) Write(mapped, rva, Read<ULONGLONG>(pe.source, rva) - delta);
                else Write(mapped, rva, Read<DWORD>(pe.source, rva) - static_cast<DWORD>(delta));
                ++result.relocations_reversed;
            }
        }
    }

    DWORD Append(std::vector<unsigned char>& bytes, const void* data, size_t count, DWORD base, DWORD alignment = 1) {
        if (bytes.size() > max_image_size || count > max_image_size - bytes.size()) Fail("Rebuilt imports exceed size limit.");
        auto offset = Align(static_cast<DWORD>(bytes.size()), alignment);
        if (offset > max_image_size || count > max_image_size - offset || base > MAXDWORD - offset)
            Fail("Rebuilt import offset overflow.");
        bytes.resize(offset + count);
        if (data && count) memcpy(bytes.data() + offset, data, count);
        return base + offset;
    }
}

namespace win_obj::dump {
    bool Snapshot::Available(size_t offset, size_t count) const {
        if (!Range(offset, count, image.size()) || pages.size() != PageCount(static_cast<ULONG>(image.size()))) return false;
        while (count) {
            auto page = offset / page_size;
            auto start = offset % page_size;
            auto bytes = (std::min)(count, page_size - start);
            if (pages[page].copied > page_size || start + bytes > pages[page].copied) return false;
            offset += bytes;
            count -= bytes;
        }
        return true;
    }

    std::vector<ExportSymbol> ReadExports(const Snapshot& snapshot) {
        Pe pe(snapshot);
        auto directory = pe.Directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (!directory.VirtualAddress && !directory.Size) return {};
        if (directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || !pe.Mapped(directory.VirtualAddress, directory.Size))
            Fail("Invalid export directory.");
        auto table = Read<IMAGE_EXPORT_DIRECTORY>(snapshot, directory.VirtualAddress);
        if (table.NumberOfFunctions > 65536 || table.NumberOfNames > 65536) Fail("Export count exceeds limit.");
        std::vector<ExportSymbol> symbols;
        std::vector<std::string> names(table.NumberOfFunctions);
        for (DWORD i = 0; i < table.NumberOfNames; ++i) {
            auto ordinal = Read<WORD>(snapshot, static_cast<size_t>(table.AddressOfNameOrdinals) + i * sizeof(WORD));
            if (ordinal >= table.NumberOfFunctions) Fail("Invalid export ordinal index.");
            auto rva = Read<DWORD>(snapshot, static_cast<size_t>(table.AddressOfNames) + i * sizeof(DWORD));
            names[ordinal] = String(snapshot, rva);
        }
        for (DWORD i = 0; i < table.NumberOfFunctions; ++i) {
            auto rva = Read<DWORD>(snapshot, static_cast<size_t>(table.AddressOfFunctions) + i * sizeof(DWORD));
            if (!rva) continue;
            if (rva >= snapshot.image.size() || table.Base > 65535 || i > 65535 - table.Base) Fail("Invalid export address/ordinal.");
            ExportSymbol symbol;
            symbol.symbol = { names[i], static_cast<WORD>(table.Base + i), names[i].empty() };
            if (rva >= directory.VirtualAddress && rva - directory.VirtualAddress < directory.Size)
                symbol.forwarder = String(snapshot, rva);
            else symbol.address = snapshot.module.base + rva;
            symbols.push_back(std::move(symbol));
        }
        return symbols;
    }

    RebuiltImage RebuildImage(const Snapshot& snapshot, bool preferred_base, const ImportResolver& resolver) {
        Pe pe(snapshot);
        RebuiltImage result;
        result.preferred_base = pe.header.ImageBase;
        result.output_base = preferred_base ? pe.header.ImageBase : snapshot.module.base;
        auto mapped = snapshot.image;
        auto header = pe.header;
        header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        for (DWORD i = pe.header.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) header.DataDirectory[i] = {};
        header.ImageBase = result.output_base;
        header.CheckSum = 0;
        // These contain disk-only offsets, stale binding state, or load-time state.
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
        if (header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
            Fail("Delay imports require a dedicated reconstruction path; raw capture was preserved.");
        Relocations(pe, mapped, preferred_base, result, header);
        auto groups = Imports(pe, resolver);
        std::vector<unsigned char> extra;
        auto extra_rva = Align(header.SizeOfImage, header.SectionAlignment);
        if (!groups.empty()) {
            extra.resize((groups.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            for (size_t i = 0; i < groups.size(); ++i) {
                const auto& group = groups[i];
                IMAGE_IMPORT_DESCRIPTOR desc{};
                desc.Name = Append(extra, group.module.c_str(), group.module.size() + 1, extra_rva);
                desc.FirstThunk = group.first_thunk;
                desc.OriginalFirstThunk = Append(extra, nullptr, (group.entries.size() + 1) * sizeof(ULONGLONG), extra_rva, 8);
                for (size_t j = 0; j < group.entries.size(); ++j) {
                    const auto& entry = group.entries[j];
                    ULONGLONG thunk = IMAGE_ORDINAL_FLAG64 | entry.symbol.ordinal;
                    if (!entry.symbol.by_ordinal) {
                        thunk = Append(extra, nullptr, sizeof(WORD), extra_rva, 2);
                        Append(extra, entry.symbol.name.c_str(), entry.symbol.name.size() + 1, extra_rva);
                    }
                    Write(extra, desc.OriginalFirstThunk - extra_rva + j * sizeof(thunk), thunk);
                    Write(mapped, entry.iat_rva, thunk);
                    result.imports.push_back(entry);
                }
                Write(extra, i * sizeof(desc), desc);
            }
            header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = { extra_rva, static_cast<DWORD>((groups.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)) };
            // Keep valid original IAT bounds: load-config/retpoline metadata can index
            // slots relative to this directory. Import descriptors retain exact RVAs.
            auto iat = pe.Directory(IMAGE_DIRECTORY_ENTRY_IAT);
            if (!iat.VirtualAddress || !iat.Size || !pe.Mapped(iat.VirtualAddress, iat.Size))
                header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
            IMAGE_SECTION_HEADER section{};
            memcpy(section.Name, ".wodimp", 7);
            section.VirtualAddress = extra_rva;
            section.Misc.VirtualSize = static_cast<DWORD>(extra.size());
            section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
            pe.sections.push_back(section);
            if (extra.size() > max_image_size || extra_rva > max_image_size - extra.size()) Fail("Rebuilt image exceeds size limit.");
            header.SizeOfImage = Align(extra_rva + static_cast<DWORD>(extra.size()), header.SectionAlignment);
        }
        auto headers_size = Align(pe.section_table + static_cast<DWORD>(pe.sections.size()) * sizeof(IMAGE_SECTION_HEADER), header.FileAlignment);
        headers_size = (std::max)(headers_size, header.SizeOfHeaders);
        for (const auto& section : pe.sections)
            if (section.VirtualAddress < headers_size) Fail("No virtual space for reconstructed PE headers.");
        result.bytes.resize(headers_size);
        memcpy(result.bytes.data(), mapped.data(), pe.header.SizeOfHeaders);
        header.SizeOfHeaders = headers_size;
        header.SizeOfCode = header.SizeOfInitializedData = header.SizeOfUninitializedData = 0;
        for (size_t i = 0; i < pe.sections.size(); ++i) {
            auto& section = pe.sections[i];
            bool added = i == pe.file.NumberOfSections;
            auto size = added ? static_cast<DWORD>(extra.size()) : (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            section.SizeOfRawData = Align(size, header.FileAlignment);
            section.PointerToRawData = static_cast<DWORD>(result.bytes.size());
            section.PointerToRelocations = section.PointerToLinenumbers = 0;
            section.NumberOfRelocations = section.NumberOfLinenumbers = 0;
            if (section.SizeOfRawData > max_image_size || result.bytes.size() > max_image_size - section.SizeOfRawData)
                Fail("Reconstructed file exceeds size limit.");
            result.bytes.resize(result.bytes.size() + section.SizeOfRawData);
            memcpy(result.bytes.data() + section.PointerToRawData, added ? extra.data() : mapped.data() + section.VirtualAddress, size);
            if (section.Characteristics & IMAGE_SCN_CNT_CODE) header.SizeOfCode += section.SizeOfRawData;
            if (section.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
                // Captured BSS is now initialized data in the analysis file.
                section.Characteristics &= ~IMAGE_SCN_CNT_UNINITIALIZED_DATA;
                section.Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
                header.SizeOfInitializedData += section.SizeOfRawData;
            }
            Write(result.bytes, pe.section_table + i * sizeof(section), section);
        }
        // Debug entries contain raw-file pointers. Recompute from unchanged RVAs.
        auto debug = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        bool debug_ok = !debug.Size || (debug.Size % sizeof(IMAGE_DEBUG_DIRECTORY) == 0 && snapshot.Available(debug.VirtualAddress, debug.Size));
        auto raw_offset = [&](DWORD rva, DWORD count) -> std::optional<size_t> {
            for (const auto& s : pe.sections)
                if (rva >= s.VirtualAddress && Range(rva - s.VirtualAddress, count, s.SizeOfRawData))
                    return static_cast<size_t>(s.PointerToRawData) + rva - s.VirtualAddress;
            return std::nullopt;
        };
        if (debug_ok && debug.Size) {
            for (DWORD i = 0; i < debug.Size; i += sizeof(IMAGE_DEBUG_DIRECTORY)) {
                auto entry = Read<IMAGE_DEBUG_DIRECTORY>(snapshot, static_cast<size_t>(debug.VirtualAddress) + i);
                auto destination = raw_offset(debug.VirtualAddress + i, sizeof(entry));
                auto data = raw_offset(entry.AddressOfRawData, entry.SizeOfData);
                if (!destination || !data || !snapshot.Available(entry.AddressOfRawData, entry.SizeOfData)) { debug_ok = false; break; }
                entry.PointerToRawData = static_cast<DWORD>(*data);
                Write(result.bytes, *destination, entry);
            }
        }
        if (!debug_ok) { header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {}; result.warnings.push_back("Unreadable or disk-only debug metadata was removed."); }
        pe.file.NumberOfSections = static_cast<WORD>(pe.sections.size());
        pe.file.PointerToSymbolTable = pe.file.NumberOfSymbols = 0;
        if (!header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) pe.file.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        Write(result.bytes, pe.nt + sizeof(DWORD), pe.file);
        Write(result.bytes, pe.optional, header);
        if (!snapshot.Available(0, snapshot.image.size())) result.warnings.push_back("Unreadable memory is zero-filled. Consult the page map before interpreting those ranges.");
        result.warnings.push_back("Live capture is not atomic. This reconstructed PE is for analysis, not loading or signature verification.");
        if (!result.imports.empty()) result.warnings.push_back("IAT pointers were replaced with lookup thunks for disassembly; original live pointers remain in the raw capture and manifest.");
        return result;
    }
}
