#include "pe.h"
#include "exception.h"
#include <iostream>



PIMAGE_SECTION_HEADER PE::findHeaderOfContainingSection(unsigned long long virtualAddress) const {
    const auto sections = this->getCommitableSectionHeaders();
    const auto sectionsCount = this->getSectionCount();
    for (int i = 0; i < sectionsCount; i++) {
        const auto currentSection = &sections[i];
        if (currentSection->VirtualAddress <= virtualAddress && virtualAddress < currentSection->
            VirtualAddress + currentSection->Misc.VirtualSize) {
            return currentSection;
        }
    }
    return nullptr;
}

char* PE::getPointerFromRva(unsigned long long virtualAddress) const {
    auto containingSection = this->findHeaderOfContainingSection(virtualAddress);
    if (!containingSection) {
        throw InvalidVirtualAddressException("Cannot find a section that accommodates this virtual address.");
    }
    auto resultPointer = this->fileBuffer + containingSection->PointerToRawData - containingSection->VirtualAddress +
                         virtualAddress;
    if (resultPointer < this->fileBuffer || resultPointer >= this->fileBuffer + this->fileSize) {
        throw InvalidVirtualAddressException("RVA address is invalid.");
    }
    return static_cast<char*>(resultPointer);
}

void PE::destroy() const {
    CloseHandle(this->fileHandle);
    CloseHandle(this->mappingHandle);
    UnmapViewOfFile(this->fileBuffer);
}

PIMAGE_NT_HEADERS PE::getDummyNtHeaders() const {
    const auto dummyHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        this->fileBuffer + this->getCommitableDosHeader()->e_lfanew);
    if (dummyHeader->Signature != IMAGE_NT_SIGNATURE) {
        throw InvalidNtHeaderException("Invalid NT header signature.");
    }
    return dummyHeader;
}
