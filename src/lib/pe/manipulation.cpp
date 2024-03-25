#include <pe.h>
#include "helpers.h"
#include "exception.h"
#include "iostream"


PIMAGE_SECTION_HEADER PE::pushNewSection(std::string &name, DWORD size, DWORD characteristics) {

    WORD numberOfSections;
    DWORD sectionAlignment;
    DWORD fileAlignment;

    DWORD newPhysicalStart;
    DWORD newVirtualStart;
    DWORD newPhysicalSize;
    DWORD newVirtualSize;

    {
        if (this->getFormat() == IMAGE_FORMAT_PE32) {
            auto header = this->getCommitableNtHeaders32();
            numberOfSections = header->FileHeader.NumberOfSections;
            sectionAlignment = header->OptionalHeader.SectionAlignment;
            fileAlignment = header->OptionalHeader.FileAlignment;
        } else {
            auto header = this->getCommitableNtHeaders64();
            numberOfSections = header->FileHeader.NumberOfSections;
            sectionAlignment = header->OptionalHeader.SectionAlignment;
            fileAlignment = header->OptionalHeader.FileAlignment;
        }

        // Need to gather all section's end positions so that we can insert a new section at the end of both the physical PE
        // file and the virtual mapping.
        auto virtualEnds = static_cast<DWORD *>(calloc(numberOfSections, sizeof(DWORD)));
        auto physicalEnds = static_cast<DWORD *>(calloc(numberOfSections, sizeof(DWORD)));

        // Need to make sure that a new section header can be inserted, otherwise, the first section on the physical media will be corrupted.
        auto physicalStarts = static_cast<DWORD *>(calloc(numberOfSections, sizeof(DWORD)));

        auto sections = this->getCommitableSectionHeaders();
        for (unsigned int i = 0; i < numberOfSections; i++) {
            virtualEnds[i] = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            physicalStarts[i] = sections[i].PointerToRawData;
            physicalEnds[i] = sections[i].SizeOfRawData + physicalStarts[i];
        }

        auto maxVirtualEnd = findMaximum(virtualEnds, numberOfSections);
        auto maxPhysicalEnd = findMaximum(physicalEnds, numberOfSections);
        auto minPhysicalStart = findMinimum(physicalStarts, numberOfSections);

        free(virtualEnds);
        free(physicalEnds);
        free(physicalStarts);

        auto newSectionCount = numberOfSections + 1;

        auto minPhysicalStartPointer = this->fileBuffer + minPhysicalStart;
        auto minExpectedPhysicalStartPointer = reinterpret_cast<char *>(sections + newSectionCount);

        if (minExpectedPhysicalStartPointer > minPhysicalStartPointer) {
            throw FileManipulationException(
                    "Failure to insert a new section - there is not enough available space for a header.");
        }

        newPhysicalStart = minimumDivisible(maxPhysicalEnd, fileAlignment);
        newVirtualStart = minimumDivisible(maxVirtualEnd, sectionAlignment);
        newPhysicalSize = minimumDivisible(size, fileAlignment);
        newVirtualSize = minimumDivisible(size, sectionAlignment);
    }

    this->enableEdit();
    if (newPhysicalStart + newPhysicalSize > this->fileSize) {
        std::cerr << "WARNING: Reallocation needed to fit the new section." << std::endl;
        this->resize(newPhysicalStart + newPhysicalSize);
    }

    auto sections = this->getCommitableSectionHeaders();
    auto newSectionPointer = &sections[numberOfSections];
    memset(newSectionPointer, 0, sizeof(IMAGE_SECTION_HEADER));
    newSectionPointer->PointerToRawData = newPhysicalStart;
    newSectionPointer->SizeOfRawData = newPhysicalSize;
    newSectionPointer->VirtualAddress = newVirtualStart;
    newSectionPointer->Misc.VirtualSize = newVirtualSize;
    newSectionPointer->Characteristics = characteristics;

    auto namePointer = name.c_str();
    auto toWrite = min(IMAGE_SIZEOF_SHORT_NAME, name.length());
    memcpy(reinterpret_cast<char *>(newSectionPointer->Name), namePointer, toWrite);

    if (this->getFormat() == IMAGE_FORMAT_PE32) {
        auto header = this->getCommitableNtHeaders32();
        header->FileHeader.NumberOfSections++;
        header->OptionalHeader.SizeOfImage = newVirtualStart + newVirtualSize;
    } else {
        auto header = this->getCommitableNtHeaders64();
        header->FileHeader.NumberOfSections++;
        header->OptionalHeader.SizeOfImage = newVirtualStart + newVirtualSize;
    }
    auto rawSection = this->fileBuffer + newSectionPointer->PointerToRawData;
    memset(rawSection, 0, newSectionPointer->SizeOfRawData);
    return newSectionPointer;
}

void PE::save(const char *filename) const {
    auto handle = CreateFileA(filename, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw Exception("Failed to open file " + std::string(filename));
    }
    auto writeResult = WriteFile(handle, this->fileBuffer, this->fileSize, nullptr, nullptr);
    CloseHandle(handle);
    if (!writeResult) {
        throw Exception("Failed to save to file " + std::string(filename));
    }
}

char* PE::getCommitableSectionData(PIMAGE_SECTION_HEADER section) const {
    return this->fileBuffer + section->PointerToRawData;
}

void PE::writeSectionData(PIMAGE_SECTION_HEADER section, char* buffer, DWORD bufSize) {
    this->enableEdit();
    if (section->SizeOfRawData < bufSize) {
        throw Exception("Failed to write - not enough buffer size.");
    }
    auto rawPointer = this->fileBuffer + section->PointerToRawData;
    memcpy(rawPointer, buffer, bufSize);
}
