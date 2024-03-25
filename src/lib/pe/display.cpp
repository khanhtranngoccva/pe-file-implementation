#include <iostream>
#include "helpers.h"
#include "windows.h"
#include "pe.h"
#include "exception.h"

void PE::displaySectionCharacteristics(unsigned int characteristics) {
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

void PE::displayNtFileHeader() const {
    std::cout << "FILE HEADER" << std::endl;
    PIMAGE_FILE_HEADER fileHeader;
    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        fileHeader = &this->getCommitableNtHeaders32()->FileHeader;
    } else {
        fileHeader = &this->getCommitableNtHeaders64()->FileHeader;
    }
    // Parse machine data
    std::cout << "Machine: " << this->getFormattedNtMachine() << std::endl;
    std::cout << "Number of sections: " << fileHeader->NumberOfSections << std::endl;
    std::cout << "Number of symbols: " << fileHeader->NumberOfSymbols << std::endl;
    std::cout << "Timestamp: " << formatTime(fileHeader->TimeDateStamp) << std::endl;
    std::cout << "Pointer to symbol table: " << hexify(fileHeader->PointerToSymbolTable) <<
            std::endl;
    std::cout << "Size of optional header: " << fileHeader->SizeOfOptionalHeader << " bytes" <<
            std::endl;
}

void PE::displayNtOptionalHeader() const {
    std::cout << "OPTIONAL HEADER" << std::endl;
    // TODO: DRY code - potentially through polymorphism
    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        const auto header = &this->getCommitableNtHeaders32()->OptionalHeader;
        std::cout << "Size of image: " << header->SizeOfImage << " bytes" << std::endl;
        std::cout << "Subsystem: " << this->getFormattedNtSubsystem() << std::endl;
        std::cout << "Address of entry point: " << hexify(header->AddressOfEntryPoint) << std::endl;
        std::cout << "Checksum: " << hexify(header->CheckSum) << std::endl;
        std::cout << "Image base: " << hexify(header->ImageBase) << std::endl;
        std::cout << "Loader flags: " << hexify(header->LoaderFlags) << std::endl;
        std::cout << "File alignment: " << header->FileAlignment << " bytes" << std::endl;
        std::cout << "Section alignment: " << header->SectionAlignment << " bytes" << std::endl;
    } else {
        const auto header = &this->getCommitableNtHeaders64()->OptionalHeader;
        std::cout << "Size of image: " << header->SizeOfImage << " bytes" << std::endl;
        std::cout << "Subsystem: " << this->getFormattedNtSubsystem() << std::endl;
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

void PE::displaySections() const {
    const unsigned int numberOfSections = this->getSectionCount();
    std::cout << "SECTIONS" << std::endl;
    for (unsigned int i = 0; i < numberOfSections; i++) {
        std::cout << std::endl;
        auto currentSectionHeader = &this->getCommitableSectionHeaders()[i];
        // Possibly no null-terminator in the name of the section. Must add it manually.
        char name[IMAGE_SIZEOF_SHORT_NAME + 1];
        memcpy(name, &currentSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME);
        name[IMAGE_SIZEOF_SHORT_NAME] = 0;
        std::cout << i << ": " << name << std::endl;
        std::cout << "Virtual size: " << currentSectionHeader->Misc.VirtualSize << " bytes" << std::endl;
        std::cout << "Virtual modifier: " << hexify(currentSectionHeader->VirtualAddress) << std::endl;
        std::cout << "Raw data size: " << currentSectionHeader->SizeOfRawData << " bytes" << std::endl;
        std::cout << "Raw data modifier: " << hexify(currentSectionHeader->PointerToRawData) << std::endl;
        std::cout << "Characteristics: " << hexify(currentSectionHeader->Characteristics) << std::endl;
        PE::displaySectionCharacteristics(currentSectionHeader->Characteristics);
    }
}

void PE::displayImports() const {
    std::cout << "IMPORTS" << std::endl;
    PIMAGE_DATA_DIRECTORY dataDir = this->getCommitableDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);

    // subtract virtual modifier because the pointer to raw data is relative to the image base, not the start of the section.
    auto importDescriptors = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(this->getPointerFromRva(dataDir->VirtualAddress));
    char zeroBufImportDesc[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = {};

    for (int i = 0;; i++) {
        IMAGE_IMPORT_DESCRIPTOR descriptor = importDescriptors[i];
        // The import table ends with an entry that is completely zero
        if (!memcmp(&descriptor, zeroBufImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        std::string libraryName = static_cast<char *>(this->getPointerFromRva(descriptor.Name));
        if (this->getFormat() == IMAGE_FORMAT_PE32) {
            char zeroBufThunkData[sizeof(IMAGE_THUNK_DATA32)] = {};
            auto thunkArray = reinterpret_cast<PIMAGE_THUNK_DATA32>(this->getPointerFromRva(
                descriptor.FirstThunk ? descriptor.FirstThunk : descriptor.OriginalFirstThunk));
            for (unsigned int i = 0;; i++) {
                auto thunkData = &thunkArray[i];
                auto isOrdinal = !!((1 << 31) & thunkData->u1.AddressOfData);
                if (!memcmp(thunkData, zeroBufThunkData, sizeof(IMAGE_THUNK_DATA32))) {
                    break;
                }
                if (isOrdinal) {
                    std::cout << "Ordinal import: Library: " << libraryName << " Ordinal: " << (
                        thunkData->u1.Ordinal ^ 0xFFFF) << std::endl;
                } else {
                    auto nameHintPair = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->getPointerFromRva(
                        thunkData->u1.AddressOfData));
                    std::cout << "Named import: Library: " << libraryName << " Name: " << nameHintPair->Name <<
                            " Hint: " << nameHintPair->Hint << std::endl;
                }
            }
        } else {
            char zeroBufThunkData[sizeof(IMAGE_THUNK_DATA64)] = {};
            auto thunkArray = reinterpret_cast<PIMAGE_THUNK_DATA64>(this->getPointerFromRva(
                descriptor.FirstThunk ? descriptor.FirstThunk : descriptor.OriginalFirstThunk));
            for (unsigned int i = 0;; i++) {
                auto thunkData = &thunkArray[i];
                auto isOrdinal = !!((1 << 63) & thunkData->u1.AddressOfData);
                if (!memcmp(thunkData, zeroBufThunkData, sizeof(IMAGE_THUNK_DATA64))) {
                    break;
                }
                if (isOrdinal) {
                    std::cout << "Ordinal import: Library: " << libraryName << " Ordinal: " << (
                        thunkData->u1.Ordinal ^ 0xFFFF) << std::endl;
                } else {
                    auto nameHintPair = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->getPointerFromRva(
                        thunkData->u1.AddressOfData));
                    std::cout << "Named import: Library: " << libraryName << " Name: " << nameHintPair->Name <<
                            " Hint: " << nameHintPair->Hint << std::endl;
                }
            }
        }
    }
}

void PE::displayExports() const {
    PIMAGE_DATA_DIRECTORY dataDir = getCommitableDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);

    char* rawExportPointer;
    try {
        rawExportPointer = this->getPointerFromRva(dataDir->VirtualAddress);
    } catch (InvalidVirtualAddressException &) {
        std::cerr << "Invalid export virtual modifier. PE file may have been packed or obfuscated.";
        return;
    }
    std::cout << "EXPORTS" << std::endl;
    auto exportTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(rawExportPointer);
    std::cout << "Internal module name: " << this->getPointerFromRva(exportTable->Name) << std::endl;
    std::cout << "Starting ordinal number: " << exportTable->Base << std::endl;
    std::cout << "Total number of functions: " << exportTable->NumberOfFunctions << std::endl;
    std::cout << "Number of named exports: " << exportTable->NumberOfNames << std::endl;
    auto processedAddresses = static_cast<bool *>(calloc(exportTable->NumberOfFunctions, sizeof(bool)));
    memset(processedAddresses, false, exportTable->NumberOfFunctions);
    auto addressTable = reinterpret_cast<DWORD *>(this->getPointerFromRva(exportTable->AddressOfFunctions));
    auto namedExportTable = reinterpret_cast<DWORD *>(this->getPointerFromRva(exportTable->AddressOfNames));
    auto namedExportOrdinalTable = reinterpret_cast<WORD *>(this->getPointerFromRva(exportTable->AddressOfNameOrdinals));

    for (int i = 0; i < exportTable->NumberOfNames; i++) {
        std::string name = static_cast<char *>(this->getPointerFromRva(namedExportTable[i]));
        const auto ordinal = namedExportOrdinalTable[i];
        auto address = addressTable[ordinal];
        auto biasedOrdinal = ordinal + exportTable->Base;
        std::cout << "Named export: Ordinal: " << biasedOrdinal << " Name: " << name << " Address: " << hexify(address)
                << std::endl;
        processedAddresses[ordinal] = true;
    }

    for (int i = 0; i < exportTable->NumberOfFunctions; i++) {
        if (!processedAddresses[i]) {
            std::cout << "Ordinal export: Ordinal: " << i + exportTable->Base << " Address: " << hexify(addressTable[i])
                    << std::endl;
        }
    }

    free(processedAddresses);
}
