#include <cstdlib>
#include <exception>
#include <windows.h>
#include <iostream>
#include "helpers.h"
#include "windows-constants.h"
#include "exception.h"

#define IMAGE_FORMAT_PE32 32
#define IMAGE_FORMAT_PE64 64
#define IMAGE_FORMAT_INVALID (-1)

int main(int argc, const char **argv);


class PE {
    HANDLE fileHandle = nullptr;
    HANDLE mappingHandle = nullptr;
    LPVOID fileBuffer = nullptr;
    unsigned int format = -1;
    unsigned long long fileSize;

    [[nodiscard]] bool checkHasValidDosHeader() const {
        if (!this->dosHeader) return false;
        return this->dosHeader->e_magic == IMAGE_DOS_SIGNATURE;
    }

    [[nodiscard]] bool checkHasValidNtHeader() const {
        if (this->ntHeaders64 != nullptr) {
            return this->ntHeaders64->Signature == IMAGE_NT_SIGNATURE;
        } else if (this->ntHeaders32 != nullptr) {
            return this->ntHeaders32->Signature == IMAGE_NT_SIGNATURE;
        } else {
            return false;
        };
    }

    [[nodiscard]] bool populateByteArchitecture() noexcept {
        // Since the magic number has the same offset and size, the code flow can share.
        const auto ntHeaders = static_cast<PIMAGE_NT_HEADERS>(this->fileBuffer + this->dosHeader->e_lfanew);
        switch (ntHeaders->OptionalHeader.Magic) {
            case 0x10b:
                this->format = 32;
                return true;
                break;
            case 0x20b:
                this->format = 64;
                return true;
                break;
            default:
                this->format = -1;
                return false;
                break;
        }
    }

    [[nodiscard]] std::string getNtMachine() const {
        switch (this->ntHeaders64->FileHeader.Machine) {
            case IMAGE_FILE_MACHINE_I386:
                return "I386 (32-bit Intel)";
            case IMAGE_FILE_MACHINE_R3000:
                return "R3000";
            case IMAGE_FILE_MACHINE_R4000:
                return "R4000";
            case IMAGE_FILE_MACHINE_R10000:
                return "R10000";
            case IMAGE_FILE_MACHINE_AM33:
                return "AM33";
            case IMAGE_FILE_MACHINE_IA64:
                return "IA64";
            case IMAGE_FILE_MACHINE_M32R:
                return "M32R";
            case IMAGE_FILE_MACHINE_SH3:
                return "SH3";
            case IMAGE_FILE_MACHINE_SH4:
                return "SH4";
            case IMAGE_FILE_MACHINE_SH5:
                return "SH5";
            case IMAGE_FILE_MACHINE_AMD64:
                return "AMD64 (64-bit Intel/AMD)";
            case IMAGE_FILE_MACHINE_ARM:
                return "ARM";
            case IMAGE_FILE_MACHINE_ARM64:
                return "ARM64";
            case IMAGE_FILE_MACHINE_AXP64:
                return "AXP64";
            case IMAGE_FILE_MACHINE_CEE:
                return "CEE";
            case IMAGE_FILE_MACHINE_CEF:
                return "CEF";
            case IMAGE_FILE_MACHINE_EBC:
                return "EBC";
            case IMAGE_FILE_MACHINE_SH3E:
                return "SH3E";
            case IMAGE_FILE_MACHINE_ARMV7:
                return "ARMV7";
            case IMAGE_FILE_MACHINE_MIPS16:
                return "MIPS16";
            case IMAGE_FILE_MACHINE_MIPSFPU:
                return "MIPSFPU";
            case IMAGE_FILE_MACHINE_MIPSFPU16:
                return "MIPSFPU16";
            case IMAGE_FILE_MACHINE_POWERPC:
                return "POWERPC";
            case IMAGE_FILE_MACHINE_POWERPCFP:
                return "POWERPCFP";
            case IMAGE_FILE_MACHINE_ALPHA:
                return "ALPHA";
            default:
                return "UNKNOWN";
        }
    }

    [[nodiscard]] static std::string getNtSubsystem(const WORD subsystem) {
        switch (subsystem) {
            case IMAGE_SUBSYSTEM_XBOX:
                return "XBOX";
            case IMAGE_SUBSYSTEM_OS2_CUI:
                return "OS2_CUI";
            case IMAGE_SUBSYSTEM_EFI_ROM:
                return "EFI_ROM";
            case IMAGE_SUBSYSTEM_NATIVE:
                return "NATIVE";
            case IMAGE_SUBSYSTEM_UNKNOWN:
                return "UNKNOWN";
            case IMAGE_SUBSYSTEM_POSIX_CUI:
                return "POSIX_CUI";
            case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                return "WINDOWS_CUI";
            case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                return "WINDOWS_GUI";
            case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
                return "WINDOWS_CE_GUI";
            case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
                return "NATIVE_WINDOWS";
            case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                return "EFI_APPLICATION";
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                return "EFI_RUNTIME_DRIVER";
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                return "EFI_BOOT_SERVICE_DRIVER";
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                return "WINDOWS_BOOT_APPLICATION";
            default:
                return "UNKNOWN";
        }
    }

    static void displaySectionCharacteristics(unsigned int characteristics) {
        std::cout << "[OBJECT FILE] Pad to next boundary: " << maskMatchStr(characteristics, 0x00000008) << std::endl;
        std::cout << "Contains executable code: " << maskMatchStr(characteristics, 0x00000020) << std::endl;
        std::cout << "Contains initialized data: " << maskMatchStr(characteristics, 0x00000040) << std::endl;
        std::cout << "Contains uninitialized data: " << maskMatchStr(characteristics, 0x00000080) << std::endl;
        std::cout << "[OBJECT FILE] Contains comments for the linker: " << maskMatchStr(characteristics, 0x00000200) <<
                std::endl;
        std::cout << "[OBJECT FILE] Not included in final image: " << maskMatchStr(characteristics, 0x00000800) <<
                std::endl;
        std::cout << "[OBJECT FILE] Contains COMDAT data: " << maskMatchStr(characteristics, 0x00001000) << std::endl;
        std::cout << "Contains data referenced through global pointer: " << maskMatchStr(characteristics, 0x00008000) <<
                std::endl;
        const int maskedAlignment = (static_cast<int>(characteristics & 0x00E00000) >> 5) - 1;
        const int alignmentBytes = maskedAlignment >= 0 ? 1 << maskedAlignment : 0;
        std::cout << "[OBJECT FILE] Data alignment boundary size: " << alignmentBytes << " bytes" << std::endl;
        std::cout << "Contains extended relocations: " << maskMatchStr(characteristics, 0x01000000) << std::endl;
        std::cout << "Can be discarded as needed: " << maskMatchStr(characteristics, 0x02000000) << std::endl;
        std::cout << "Cacheable: " << boolStr(!maskMatch(characteristics, 0x04000000)) << std::endl;
        std::cout << "Pageable: " << boolStr(!maskMatch(characteristics, 0x08000000)) << std::endl;
        std::cout << "Shareable: " << maskMatchStr(characteristics, 0x10000000) << std::endl;
        std::cout << "Executable: " << maskMatchStr(characteristics, 0x20000000) << std::endl;
        std::cout << "Readable: " << maskMatchStr(characteristics, 0x40000000) << std::endl;
        std::cout << "Writeable: " << maskMatchStr(characteristics, 0x80000000) << std::endl;
    }

    [[nodiscard]] PIMAGE_SECTION_HEADER findContainingSection(unsigned long long virtualAddress) const {
        IMAGE_FILE_HEADER fileHeader;
        if (this->ntHeaders32) {
            fileHeader = this->ntHeaders32->FileHeader;
        } else if (this->ntHeaders64) {
            fileHeader = this->ntHeaders64->FileHeader;
        } else {
            throw InvalidNtHeaderException("No valid NT headers found.");
        }
        for (int i = 0; i < fileHeader.NumberOfSections; i++) {
            auto currentSection = &this->sectionHeaders[i];
            if (currentSection->VirtualAddress <= virtualAddress && virtualAddress < currentSection->
                VirtualAddress + currentSection->Misc.VirtualSize) {
                return currentSection;
            }
        }
        return nullptr;
    }

    [[nodiscard]] LPVOID getPointerFromRva(unsigned long long virtualAddress) const {
        auto containingSection = this->findContainingSection(virtualAddress);
        if (!containingSection) {
            throw InvalidVirtualAddressException("Cannot find a section that accommodates this virtual address.");
        }
        auto resultPointer = this->fileBuffer + containingSection->PointerToRawData - containingSection->VirtualAddress + virtualAddress;
        if (resultPointer < this->fileBuffer || resultPointer >= this->fileBuffer + this->fileSize) {
            throw InvalidVirtualAddressException("RVA address is invalid.");
        }
        return resultPointer;
    }

public:
    PIMAGE_DOS_HEADER dosHeader = nullptr;
    PIMAGE_NT_HEADERS64 ntHeaders64 = nullptr;
    PIMAGE_NT_HEADERS32 ntHeaders32 = nullptr;
    PIMAGE_SECTION_HEADER sectionHeaders = nullptr;

    explicit PE(const char *filename) {
        try {
            this->fileHandle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL, nullptr);
            if (this->fileHandle == INVALID_HANDLE_VALUE) {
                throw Exception("Failed to open file" + std::string(filename));
            }

            LARGE_INTEGER fileSize;
            if (!GetFileSizeEx(this->fileHandle, &fileSize)) {
                throw Exception("Failed to query file size");
            };
            this->fileSize = fileSize.QuadPart;

            this->mappingHandle = CreateFileMappingA(this->fileHandle, nullptr, PAGE_READONLY, 0,
                                                     0, nullptr);
            if (this->mappingHandle == INVALID_HANDLE_VALUE) {
                throw Exception("Failed to create file mapping.");
            }

            this->fileBuffer = MapViewOfFile(this->mappingHandle, FILE_MAP_READ,
                                             0, 0, 0);
            if (this->fileBuffer == nullptr) {
                throw Exception("Failed to read file.");
            }

            this->dosHeader = static_cast<PIMAGE_DOS_HEADER>(this->fileBuffer);
            if (!this->checkHasValidDosHeader()) {
                throw InvalidDosHeaderException("This file does not have a valid DOS header.");
            }

            if (!this->populateByteArchitecture()) {
                throw InvalidPeFormatException("Unable to determine if the file is PE32 or PE32+.");
            }

            // 64-bit format NT headers and 32-bit format NT headers have different sizes.
            void *ntHeaderPointer = this->fileBuffer + this->dosHeader->e_lfanew;
            switch (this->format) {
                case IMAGE_FORMAT_PE64:
                    this->ntHeaders64 = static_cast<PIMAGE_NT_HEADERS64>(ntHeaderPointer);
                    this->sectionHeaders = static_cast<PIMAGE_SECTION_HEADER>(
                        ntHeaderPointer + sizeof(IMAGE_NT_HEADERS64));
                    break;
                case IMAGE_FORMAT_PE32:
                    this->ntHeaders32 = static_cast<PIMAGE_NT_HEADERS32>(ntHeaderPointer);
                    this->sectionHeaders = static_cast<PIMAGE_SECTION_HEADER>(
                        ntHeaderPointer + sizeof(IMAGE_NT_HEADERS32));
                    break;
                default:
                    throw InvalidPeFormatException("Invalid PE format.");
            }
            if (!this->checkHasValidNtHeader()) {
                throw InvalidNtHeaderException("This file does not have a valid NT header.");
            }
        } catch (Exception &) {
            this->destroy();
            throw;
        }
    }

    void displayNtFileHeader() const {
        std::cout << "FILE HEADER" << std::endl;
        IMAGE_FILE_HEADER fileHeader;
        if (this->ntHeaders32) {
            fileHeader = this->ntHeaders32->FileHeader;
        } else if (this->ntHeaders64) {
            fileHeader = this->ntHeaders64->FileHeader;
        } else {
            throw InvalidNtHeaderException("No valid NT headers found.");
        }
        // Parse machine data
        std::cout << "Machine: " << std::string(this->getNtMachine()) << std::endl;
        std::cout << "Number of sections: " << fileHeader.NumberOfSections << std::endl;
        std::cout << "Number of symbols: " << fileHeader.NumberOfSymbols << std::endl;
        std::cout << "Timestamp: " << formatTime(fileHeader.TimeDateStamp) << std::endl;
        std::cout << "Pointer to symbol table: " << hexify(fileHeader.PointerToSymbolTable) <<
                std::endl;
        std::cout << "Size of optional header: " << fileHeader.SizeOfOptionalHeader << " bytes" <<
                std::endl;
    }

    void displayNtOptionalHeader() const {
        std::cout << "OPTIONAL HEADER" << std::endl;
        // TODO: DRY code - potentially through polymorphism
        if (this->ntHeaders32) {
            const auto header = &this->ntHeaders32->OptionalHeader;
            std::cout << "Size of image: " << header->SizeOfImage << " bytes" << std::endl;
            std::cout << "Subsystem: " << PE::getNtSubsystem(header->Subsystem) << std::endl;
            std::cout << "Address of entry point: " << hexify(header->AddressOfEntryPoint) << std::endl;
            std::cout << "Checksum: " << hexify(header->CheckSum) << std::endl;
            std::cout << "Image base: " << hexify(header->ImageBase) << std::endl;
            std::cout << "Loader flags: " << hexify(header->LoaderFlags) << std::endl;
            std::cout << "File alignment: " << header->FileAlignment << " bytes" << std::endl;
            std::cout << "Section alignment: " << header->SectionAlignment << " bytes" << std::endl;
        } else if (this->ntHeaders64) {
            const auto header = &this->ntHeaders64->OptionalHeader;
            std::cout << "Size of image: " << header->SizeOfImage << " bytes" << std::endl;
            std::cout << "Subsystem: " << PE::getNtSubsystem(header->Subsystem) << std::endl;
            std::cout << "Address of entry point: " << hexify(header->AddressOfEntryPoint) << std::endl;
            std::cout << "Checksum: " << hexify(header->CheckSum) << std::endl;
            std::cout << "Image base: " << hexify(header->ImageBase) << std::endl;
            std::cout << "Loader flags: " << hexify(header->LoaderFlags) << std::endl;
            std::cout << "Number of valid data directory entries (RVAs and sizes): " << header->NumberOfRvaAndSizes <<
                    std::endl;
            std::cout << "File alignment: " << header->FileAlignment << " bytes" << std::endl;
            std::cout << "Section alignment: " << header->SectionAlignment << " bytes" << std::endl;
        }
    }

    void displaySections() const {
        int numberOfSections;
        if (this->ntHeaders32) {
            numberOfSections = this->ntHeaders32->FileHeader.NumberOfSections;
        } else if (this->ntHeaders64) {
            numberOfSections = this->ntHeaders64->FileHeader.NumberOfSections;
        } else {
            throw Exception("No valid NT headers found.");
        }
        std::cout << "SECTIONS" << std::endl;
        for (int i = 0; i < numberOfSections; i++) {
            std::cout << std::endl;
            auto currentSectionHeader = &this->sectionHeaders[i];
            // Possibly no null-terminator in the name of the section. Must add it manually.
            char name[IMAGE_SIZEOF_SHORT_NAME + 1];
            memcpy(name, &currentSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME);
            name[IMAGE_SIZEOF_SHORT_NAME] = 0;
            std::cout << i << ": " << name << std::endl;
            std::cout << "Virtual size: " << currentSectionHeader->Misc.VirtualSize << " bytes" << std::endl;
            std::cout << "Virtual address: " << hexify(currentSectionHeader->VirtualAddress) << std::endl;
            std::cout << "Raw data size: " << currentSectionHeader->SizeOfRawData << " bytes" << std::endl;
            std::cout << "Raw data address: " << hexify(currentSectionHeader->PointerToRawData) << std::endl;
            std::cout << "Characteristics: " << hexify(currentSectionHeader->Characteristics) << std::endl;
            PE::displaySectionCharacteristics(currentSectionHeader->Characteristics);
        }
    }

    void displayImports() const {
        IMAGE_DATA_DIRECTORY dataDir;
        if (this->ntHeaders32) {
            dataDir = this->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else if (this->ntHeaders64) {
            dataDir = this->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else {
            throw InvalidNtHeaderException("No valid NT headers found.");
        }
        std::cout << "IMPORTS" << std::endl;

        // subtract virtual address because the pointer to raw data is relative to the image base, not the start of the section.
        auto importDescriptors = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(this->getPointerFromRva(dataDir.VirtualAddress));
        char zeroBufImportDesc[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = {};

        for (int i = 0;; i++) {
            IMAGE_IMPORT_DESCRIPTOR descriptor = importDescriptors[i];
            // The import table ends with an entry that is completely zero
            if (!memcmp(&descriptor, zeroBufImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                break;
            }
            std::string libraryName = static_cast<char *>(this->getPointerFromRva(descriptor.Name));
            if (this->format == IMAGE_FORMAT_PE32) {
                char zeroBufThunkData[sizeof(IMAGE_THUNK_DATA32)] = {};
                auto thunkArray = static_cast<PIMAGE_THUNK_DATA32>(this->getPointerFromRva(descriptor.FirstThunk ? descriptor.FirstThunk : descriptor.OriginalFirstThunk));
                for (unsigned int i = 0;; i++) {
                    auto thunkData = &thunkArray[i];
                    auto isOrdinal = !!((1 << 31) & thunkData->u1.AddressOfData);
                    if (!memcmp(thunkData, zeroBufThunkData, sizeof(IMAGE_THUNK_DATA32))) {
                        break;
                    }
                    if (isOrdinal) {
                        std::cout << "Ordinal import: Library: " << libraryName << " Ordinal: " << (thunkData->u1.Ordinal ^ 0xFFFF) << std::endl;
                    } else {
                        auto nameHintPair = static_cast<PIMAGE_IMPORT_BY_NAME>(this->getPointerFromRva(thunkData->u1.AddressOfData));
                        std::cout << "Named import: Library: " << libraryName << " Name: " << nameHintPair->Name << " Hint: " << nameHintPair->Hint << std::endl;
                    }
                }
            } else {
                char zeroBufThunkData[sizeof(IMAGE_THUNK_DATA64)] = {};
                auto thunkArray = static_cast<PIMAGE_THUNK_DATA64>(this->getPointerFromRva(descriptor.FirstThunk ? descriptor.FirstThunk : descriptor.OriginalFirstThunk));
                for (unsigned int i = 0;; i++) {
                    auto thunkData = &thunkArray[i];
                    auto isOrdinal = !!((1 << 63) & thunkData->u1.AddressOfData);
                    if (!memcmp(thunkData, zeroBufThunkData, sizeof(IMAGE_THUNK_DATA64))) {
                        break;
                    }
                    if (isOrdinal) {
                        std::cout << "Ordinal import: Library: " << libraryName << " Ordinal: " << (thunkData->u1.Ordinal ^ 0xFFFF) << std::endl;
                    } else {
                        auto nameHintPair = static_cast<PIMAGE_IMPORT_BY_NAME>(this->getPointerFromRva(thunkData->u1.AddressOfData));
                        std::cout << "Named import: Library: " << libraryName << " Name: " << nameHintPair->Name << " Hint: " << nameHintPair->Hint << std::endl;
                    }
                }
            }
        }
    }

    void displayExports() const {
        IMAGE_DATA_DIRECTORY dataDir;
        if (this->ntHeaders32) {
            dataDir = this->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else if (this->ntHeaders64) {
            dataDir = this->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        } else {
            throw InvalidNtHeaderException("No valid NT headers found.");
        }

        LPVOID rawExportPointer;
        try {
            rawExportPointer = this->getPointerFromRva(dataDir.VirtualAddress);
        } catch (InvalidVirtualAddressException&) {
            std::cerr << "Invalid export virtual address. PE file may have been packed or obfuscated.";
            return;
        }
        std::cout << "EXPORTS" << std::endl;
        auto exportTable = static_cast<PIMAGE_EXPORT_DIRECTORY>(rawExportPointer);
        std::cout << "Internal module name: " << this->getPointerFromRva(exportTable->Name) << std::endl;
        std::cout << "Starting ordinal number: " << exportTable->Base << std::endl;
        std::cout << "Total number of functions: " << exportTable->NumberOfFunctions << std::endl;
        std::cout << "Number of named exports: " << exportTable->NumberOfNames << std::endl;
        auto processedAddresses = static_cast<bool*>(calloc(exportTable->NumberOfFunctions, sizeof(bool)));
        memset(processedAddresses, false, exportTable->NumberOfFunctions);
        auto addressTable = static_cast<DWORD*>(this->getPointerFromRva(exportTable->AddressOfFunctions));
        auto namedExportTable = static_cast<DWORD*>(this->getPointerFromRva(exportTable->AddressOfNames));
        auto namedExportOrdinalTable = static_cast<WORD*>(this->getPointerFromRva(exportTable->AddressOfNameOrdinals));

        for (int i = 0; i < exportTable->NumberOfNames; i++) {
            std::string name = static_cast<char*>(this->getPointerFromRva(namedExportTable[i]));
            const auto ordinal = namedExportOrdinalTable[i];
            auto address = addressTable[ordinal];
            auto biasedOrdinal = ordinal + exportTable->Base;
            std::cout << "Named export: Ordinal: " << biasedOrdinal << " Name: " << name << " Address: " << hexify(address) << std::endl;
            processedAddresses[ordinal] = true;
        }

        for (int i = 0; i < exportTable->NumberOfFunctions; i++) {
            if (!processedAddresses[i]) {
                std::cout << "Ordinal export: Ordinal: " << i + exportTable->Base << " Address: " << hexify(addressTable[i]) << std::endl;
            }
        }

        free(processedAddresses);
    }
    void destroy() const {
        CloseHandle(this->fileHandle);
        CloseHandle(this->mappingHandle);
        UnmapViewOfFile(this->fileBuffer);
    }
};

int main(const int argc, const char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: pefile.exe [path]" << std::endl;
        exit(1);
    }

    const char *fileName = argv[1];
    std::cout << "Analyzing: " << fileName << std::endl;

    try {
        auto pefile = PE(fileName);
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayNtFileHeader();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayNtOptionalHeader();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displaySections();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayImports();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayExports();
        pefile.destroy();
    } catch (Exception &e) {
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    return 0;
}
