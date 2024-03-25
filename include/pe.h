#pragma once

#include <string>
#include <windows.h>

#define IMAGE_FORMAT_PE32 32
#define IMAGE_FORMAT_PE64 64
#define IMAGE_FORMAT_INVALID (-1)

class PE {
    HANDLE fileHandle = nullptr;
    HANDLE mappingHandle = nullptr;
    char *fileBuffer = nullptr;
    unsigned long long fileSize;
    bool editable = false;

    static void displaySectionCharacteristics(unsigned int characteristics);

    PIMAGE_SECTION_HEADER findHeaderOfContainingSection(unsigned long long virtualAddress) const;

    char *getPointerFromRva(unsigned long long virtualAddress) const;

    PIMAGE_NT_HEADERS getDummyNtHeaders() const;

    void resize(DWORD64 bytes);

    void enableEdit();

    void destroyMappings();
public:
    explicit PE(const char *filename);

    void displayNtFileHeader() const;

    void displayNtOptionalHeader() const;

    void displaySections() const;

    void displayImports() const;

    void displayExports() const;

    void destroy();

    std::string getFormattedNtMachine() const;

    std::string getFormattedNtSubsystem() const;

    WORD getNtMachine() const;

    WORD getNtSubsystem() const;

    unsigned int getSectionCount() const;

    unsigned short int getFormat() const;

    PIMAGE_DOS_HEADER getCommitableDosHeader() const;

    PIMAGE_NT_HEADERS32 getCommitableNtHeaders32() const;

    PIMAGE_NT_HEADERS64 getCommitableNtHeaders64() const;

    PIMAGE_SECTION_HEADER getCommitableSectionHeaders() const;

    PIMAGE_DATA_DIRECTORY getCommitableDataDirectory(unsigned short int type) const;

    PIMAGE_SECTION_HEADER getCommitableSectionByName(std::string& name) const;

    char* getCommitableSectionData(PIMAGE_SECTION_HEADER section) const;

    PIMAGE_SECTION_HEADER pushNewSection(std::string& name, DWORD size, DWORD characteristics);

    void writeSectionData(PIMAGE_SECTION_HEADER section, char* buffer, DWORD bufSize);

    void save(const char* filename) const;
};
