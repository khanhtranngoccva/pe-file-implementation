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

char *PE::getPointerFromRva(unsigned long long virtualAddress) const {
    auto containingSection = this->findHeaderOfContainingSection(virtualAddress);
    if (!containingSection) {
        throw InvalidVirtualAddressException("Cannot find a section that accommodates this virtual address.");
    }
    auto resultPointer = this->fileBuffer + containingSection->PointerToRawData - containingSection->VirtualAddress +
                         virtualAddress;
    if (resultPointer < this->fileBuffer || resultPointer >= this->fileBuffer + this->fileSize) {
        throw InvalidVirtualAddressException("RVA address is invalid.");
    }
    return static_cast<char *>(resultPointer);
}

void PE::destroy() {
    if (!this->editable) {
        this->destroyMappings();
    } else {
        free(this->fileBuffer);
        this->fileBuffer = nullptr;
    }
}

void PE::destroyMappings() {
    CloseHandle(this->fileHandle);
    CloseHandle(this->mappingHandle);
    UnmapViewOfFile(this->fileBuffer);
    this->fileHandle = nullptr;
    this->mappingHandle = nullptr;
    this->fileBuffer = nullptr;
}

PIMAGE_NT_HEADERS PE::getDummyNtHeaders() const {
    const auto dummyHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(this->fileBuffer + this->getCommitableDosHeader()->e_lfanew);
    if (dummyHeader->Signature != IMAGE_NT_SIGNATURE) {
        throw InvalidNtHeaderException("Invalid NT header signature.");
    }
    return dummyHeader;
}

void PE::enableEdit() {
    if (this->editable) return;
    auto newBuf = calloc(this->fileSize, sizeof(char));
    memcpy(newBuf, this->fileBuffer, this->fileSize);
    this->editable = true;
    this->destroyMappings();
    this->fileBuffer = static_cast<char *>(newBuf);
}

void PE::resize(DWORD64 bytes) {
    this->enableEdit();
    this->fileBuffer = static_cast<char *>(realloc(this->fileBuffer, bytes));
    this->fileSize = bytes;
}