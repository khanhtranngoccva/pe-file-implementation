#include "windows-constants.h"
#include "pe.h"
#include "exception.h"
#include <iostream>

unsigned int PE::getSectionCount() const {
    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        return this->getCommitableNtHeaders32()->FileHeader.NumberOfSections;
    } else {
        return this->getCommitableNtHeaders64()->FileHeader.NumberOfSections;
    }
}

unsigned short int PE::getFormat() const {
    const auto header = this->getDummyNtHeaders();
    switch (header->OptionalHeader.Magic) {
        case 0x10b:
            return IMAGE_FORMAT_PE32;
        case 0x20b:
            return IMAGE_FORMAT_PE64;
        default:
            throw InvalidNtHeaderException("No valid NT header was found.");
    }
}

PIMAGE_NT_HEADERS32 PE::getCommitableNtHeaders32() const {
    const auto header = this->getDummyNtHeaders();
    if (header->OptionalHeader.Magic != 0x10b) {
        throw InvalidNtHeaderException("No valid PE32 NT header was found.");
    }
    return static_cast<PIMAGE_NT_HEADERS32>(static_cast<void*>(header));
}

PIMAGE_NT_HEADERS64 PE::getCommitableNtHeaders64() const {
    auto header = this->getDummyNtHeaders();
    if (header->OptionalHeader.Magic != 0x20b) {
        throw InvalidNtHeaderException("No valid PE32+ NT header was found.");
    }
    return static_cast<PIMAGE_NT_HEADERS64>(static_cast<void*>(header));
}

PIMAGE_SECTION_HEADER PE::getCommitableSectionHeaders() const {
    const auto format = this->getFormat();
    PIMAGE_SECTION_HEADER out;
    if (format == IMAGE_FORMAT_PE32) {
        const auto header = reinterpret_cast<char*>(this->getCommitableNtHeaders32());
        out = reinterpret_cast<PIMAGE_SECTION_HEADER>(header + sizeof(IMAGE_NT_HEADERS32));
    } else {
        const auto header = reinterpret_cast<char*>(this->getCommitableNtHeaders64());
        out = reinterpret_cast<PIMAGE_SECTION_HEADER>(header + sizeof(IMAGE_NT_HEADERS64));
    }
    return out;
}

PIMAGE_DOS_HEADER PE::getCommitableDosHeader() const {
    const auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->fileBuffer);
    if (header->e_magic != IMAGE_DOS_SIGNATURE) {
        throw InvalidDosHeaderException("Invalid DOS header.");
    }
    return header;
}

PIMAGE_DATA_DIRECTORY PE::getCommitableDataDirectory(unsigned short int type) const {
    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        return &(this->getCommitableNtHeaders32()->OptionalHeader.DataDirectory[type]);
    } else {
        return &(this->getCommitableNtHeaders64()->OptionalHeader.DataDirectory[type]);
    }
}

WORD PE::getNtMachine() const {
    PIMAGE_FILE_HEADER fileHeader;

    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        fileHeader = &this->getCommitableNtHeaders32()->FileHeader;
    } else {
        fileHeader = &this->getCommitableNtHeaders64()->FileHeader;
    }

    return fileHeader->Machine;
}

WORD PE::getNtSubsystem() const {
    WORD subsystem;

    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        subsystem = this->getCommitableNtHeaders32()->OptionalHeader.Subsystem;
    } else {
        subsystem = this->getCommitableNtHeaders64()->OptionalHeader.Subsystem;
    }

    return subsystem;
}

std::string PE::getFormattedNtMachine() const {
    switch (this->getNtMachine()) {
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

std::string PE::getFormattedNtSubsystem() const {
    switch (this->getNtSubsystem()) {
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
