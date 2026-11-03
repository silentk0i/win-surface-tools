#include "dump/pe/pe-rebuild.h"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
    using namespace win_obj::dump;
    constexpr size_t nt = 0x80;
    constexpr size_t optional = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    constexpr size_t sections = optional + sizeof(IMAGE_OPTIONAL_HEADER64);
    constexpr ULONGLONG preferred = 0x140000000ull;
    constexpr ULONGLONG loaded = 0xfffff80210000000ull;
    template<class T> void Put(std::vector<unsigned char>& bytes, size_t offset, T value) { memcpy(bytes.data() + offset, &value, sizeof(value)); }
    template<class T> T Get(const std::vector<unsigned char>& bytes, size_t offset) { T value; memcpy(&value, bytes.data() + offset, sizeof(value)); return value; }
    void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
    template<class Function> void Reject(Function function, const char* message) {
        try { function(); }
        catch (const std::runtime_error&) { return; }
        throw std::runtime_error(message);
    }
    Snapshot Fixture() {
        Snapshot image;
        image.module.base = loaded;
        image.module.size = 0x5000;
        strcpy_s(image.module.path, "\\SystemRoot\\fixture.sys");
        image.image.resize(image.module.size);
        image.pages.resize(5, { page_size, 0 });
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = nt;
        Put(image.image, 0, dos);
        Put(image.image, nt, static_cast<DWORD>(IMAGE_NT_SIGNATURE));
        IMAGE_FILE_HEADER file{};
        file.Machine = IMAGE_FILE_MACHINE_AMD64;
        file.NumberOfSections = 4;
        file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_SYSTEM;
        Put(image.image, nt + sizeof(DWORD), file);
        IMAGE_OPTIONAL_HEADER64 header{};
        header.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        header.ImageBase = preferred;
        header.AddressOfEntryPoint = 0x1000;
        header.SectionAlignment = 0x1000;
        header.FileAlignment = 0x200;
        header.SizeOfHeaders = 0x400;
        header.SizeOfImage = 0x5000;
        header.Subsystem = IMAGE_SUBSYSTEM_NATIVE;
        header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        header.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = { 0x2000, 40 };
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = { 0x2100, 24 };
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0x4000, 12 };
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = { 0x9000, 0x100 };
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = { 0x2300, 8 };
        Put(image.image, optional, header);
        const char* names[] = { ".text", ".idata", ".data", ".reloc" };
        for (DWORD i = 0; i < 4; ++i) {
            IMAGE_SECTION_HEADER section{};
            strcpy_s(reinterpret_cast<char*>(section.Name), sizeof(section.Name), names[i]);
            section.VirtualAddress = (i + 1) * 0x1000;
            section.Misc.VirtualSize = 0x1000;
            section.SizeOfRawData = i == 2 ? 0 : 0x200;
            section.PointerToRawData = 0x400 + i * 0x200;
            section.Characteristics = IMAGE_SCN_MEM_READ | (i == 0 ? IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE : IMAGE_SCN_CNT_INITIALIZED_DATA);
            Put(image.image, sections + i * sizeof(section), section);
        }
        image.image[0x1000] = 0xc3;
        Put(image.image, 0x1100, loaded + 0x3050);
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.Name = 0x2200;
        descriptor.OriginalFirstThunk = 0x2080;
        descriptor.FirstThunk = 0x2100;
        Put(image.image, 0x2000, descriptor);
        memcpy(image.image.data() + 0x2200, "ntoskrnl.exe", 13);
        Put(image.image, 0x2080, ULONGLONG{ 0x2240 });
        Put(image.image, 0x2088, IMAGE_ORDINAL_FLAG64 | ULONGLONG{ 7 });
        memcpy(image.image.data() + 0x2242, "KeExample", 10);
        Put(image.image, 0x2100, ULONGLONG{ 0xfffff80000001234 });
        Put(image.image, 0x2108, ULONGLONG{ 0xfffff80000005678 });
        image.image[0x3050] = 0xa5;
        Put(image.image, 0x4000, IMAGE_BASE_RELOCATION{ 0x1000, 12 });
        Put(image.image, 0x4008, static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x100));
        return image;
    }
    size_t Raw(const std::vector<unsigned char>& file, DWORD rva) {
        auto header = Get<IMAGE_FILE_HEADER>(file, nt + 4);
        for (WORD i = 0; i < header.NumberOfSections; ++i) {
            auto s = Get<IMAGE_SECTION_HEADER>(file, sections + i * sizeof(IMAGE_SECTION_HEADER));
            if (rva >= s.VirtualAddress && rva - s.VirtualAddress < s.SizeOfRawData) return s.PointerToRawData + rva - s.VirtualAddress;
        }
        throw std::runtime_error("No output section for RVA");
    }
}

int main() {
    try {
        auto image = Fixture();
        auto original = image.image;
        auto result = RebuildImage(image, false, {});
        auto header = Get<IMAGE_OPTIONAL_HEADER64>(result.bytes, optional);
        Check(header.ImageBase == loaded && result.relocations_reversed == 0, "Loaded base mismatch");
        Check(Get<ULONGLONG>(result.bytes, Raw(result.bytes, 0x1100)) == loaded + 0x3050, "Live pointer was changed in loaded mode");
        Check(result.imports.size() == 2 && result.imports[0].symbol.name == "KeExample" && result.imports[1].symbol.by_ordinal, "Import names/ordinals lost");
        auto descriptor = Get<IMAGE_IMPORT_DESCRIPTOR>(result.bytes, Raw(result.bytes, header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
        Check(descriptor.FirstThunk == 0x2100 && descriptor.OriginalFirstThunk >= 0x5000, "IAT RVA changed");
        auto thunk = Get<ULONGLONG>(result.bytes, Raw(result.bytes, 0x2100));
        Check(thunk >= 0x5000 && thunk < header.SizeOfImage && Get<ULONGLONG>(result.bytes, Raw(result.bytes, 0x2108)) == (IMAGE_ORDINAL_FLAG64 | 7), "IAT not rebuilt");
        Check(std::string(reinterpret_cast<const char*>(result.bytes.data() + Raw(result.bytes, static_cast<DWORD>(thunk)) + 2)) == "KeExample", "Import by name points to wrong bytes");
        Check(result.bytes[Raw(result.bytes, 0x3050)] == 0xa5, "Live initialized BSS was lost");
        Check(!header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size && !header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size, "Stale directories retained");
        Check(header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress == 0x2100 &&
            header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size == 24, "Original IAT directory needed by runtime fixups was lost");
        Check(image.image == original, "Raw evidence was modified");
        std::filesystem::create_directories("build/tests/dump");
        std::ofstream output("build/tests/dump/reconstructed.sys", std::ios::binary);
        output.write(reinterpret_cast<const char*>(result.bytes.data()), result.bytes.size());
        output.close();

        result = RebuildImage(image, true, {});
        Check(result.relocations_reversed == 1 && Get<ULONGLONG>(result.bytes, Raw(result.bytes, 0x1100)) == preferred + 0x3050, "DIR64 relocation not reversed");
        Put(image.image, 0x4008, static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x100));
        Put(image.image, 0x1100, static_cast<DWORD>(loaded + 0x3050));
        result = RebuildImage(image, true, {});
        Check(Get<DWORD>(result.bytes, Raw(result.bytes, 0x1100)) == static_cast<DWORD>(preferred + 0x3050), "HIGHLOW relocation not reversed");

        image = Fixture();
        image.pages[4] = { 0, static_cast<LONG>(0x8000000d) };
        memset(image.image.data() + 0x4000, 0, 0x1000);
        result = RebuildImage(image, false, {});
        Check(!Get<IMAGE_OPTIONAL_HEADER64>(result.bytes, optional).DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, "Missing relocations not cleared");
        Reject([&] { RebuildImage(image, true, {}); }, "Missing relocations accepted for preferred base");

        image = Fixture();
        auto descriptor2 = Get<IMAGE_IMPORT_DESCRIPTOR>(image.image, 0x2000);
        descriptor2.OriginalFirstThunk = 0;
        Put(image.image, 0x2000, descriptor2);
        unsigned resolved = 0;
        result = RebuildImage(image, false, [&](const std::string& module, ULONGLONG address) -> std::optional<ImportSymbol> {
            Check(module == "ntoskrnl.exe", "Wrong module for import recovery");
            ++resolved;
            return ImportSymbol{ address == 0xfffff80000001234 ? "RecoveredA" : "RecoveredB" };
        });
        Check(resolved == 2 && result.imports[0].recovered && result.imports[1].recovered, "Missing INT was not recovered");
        Reject([&] { RebuildImage(image, false, {}); }, "Unresolvable import was silently invented");

        image = Fixture();
        image.pages[3].copied = 64;
        memset(image.image.data() + 0x3040, 0, 0xfc0);
        result = RebuildImage(image, false, {});
        Check(!image.Available(0x303f, 2) && image.Available(0x303f, 1) && !result.warnings.empty(), "Partial-page coverage ignored");
        image.pages[0].copied = 0;
        Reject([&] { RebuildImage(image, false, {}); }, "Unreadable headers accepted");

        image = Fixture();
        Put(image.image, 0x4000, IMAGE_BASE_RELOCATION{ 0x1000, 7 });
        Reject([&] { RebuildImage(image, true, {}); }, "Malformed relocation accepted");
        image = Fixture();
        Put(image.image, 0x4008, static_cast<WORD>((9 << 12) | 0x100));
        Reject([&] { RebuildImage(image, true, {}); }, "Unknown relocation accepted");
        image = Fixture();
        auto s = Get<IMAGE_SECTION_HEADER>(image.image, sections + sizeof(IMAGE_SECTION_HEADER));
        s.VirtualAddress = 0x1000;
        Put(image.image, sections + sizeof(IMAGE_SECTION_HEADER), s);
        Reject([&] { RebuildImage(image, false, {}); }, "Overlapping section accepted");
        image = Fixture();
        header = Get<IMAGE_OPTIONAL_HEADER64>(image.image, optional);
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = { 0x2500, 32 };
        Put(image.image, optional, header);
        Reject([&] { RebuildImage(image, false, {}); }, "Delay imports silently dropped");

        image = Fixture();
        auto small_file = Get<IMAGE_FILE_HEADER>(image.image, nt + 4);
        small_file.NumberOfSections = 3;
        Put(image.image, nt + 4, small_file);
        header = Get<IMAGE_OPTIONAL_HEADER64>(image.image, optional);
        header.SizeOfHeaders = 0x200;
        header.SizeOfImage = 0x4000;
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {};
        Put(image.image, optional, header);
        image.image.resize(0x4000);
        image.module.size = 0x4000;
        image.pages.resize(4);
        result = RebuildImage(image, false, {});
        Check(Get<IMAGE_OPTIONAL_HEADER64>(result.bytes, optional).SizeOfHeaders == 0x400 && result.bytes[Raw(result.bytes, 0x1000)] == 0xc3,
            "Header growth corrupted original section RVAs");

        image = Fixture();
        header = Get<IMAGE_OPTIONAL_HEADER64>(image.image, optional);
        header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = { 0x3000, 0x200 };
        Put(image.image, optional, header);
        IMAGE_EXPORT_DIRECTORY exports{};
        exports.Base = 5;
        exports.NumberOfFunctions = 3;
        exports.NumberOfNames = 1;
        exports.AddressOfFunctions = 0x3040;
        exports.AddressOfNames = 0x3060;
        exports.AddressOfNameOrdinals = 0x3070;
        Put(image.image, 0x3000, exports);
        Put(image.image, 0x3040, DWORD{ 0x1000 });
        Put(image.image, 0x3044, DWORD{ 0x3090 });
        Put(image.image, 0x3048, DWORD{ 0x1010 });
        Put(image.image, 0x3060, DWORD{ 0x3080 });
        Put(image.image, 0x3070, WORD{ 0 });
        memcpy(image.image.data() + 0x3080, "ExportA", 8);
        memcpy(image.image.data() + 0x3090, "other.#17", 10);
        auto symbols = ReadExports(image);
        Check(symbols.size() == 3 && symbols[0].symbol.name == "ExportA" && symbols[0].address == loaded + 0x1000 &&
            symbols[1].forwarder == "other.#17" && symbols[2].symbol.by_ordinal && symbols[2].symbol.ordinal == 7, "Export recovery failed");
        std::cout << "PE reconstruction tests passed (imports, exports, relocations, coverage, malformed images).\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
