#include "pe.h"
#include <windows.h>
#include "exception.h"

PE::PE(const char *filename) {
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

        this->fileBuffer = static_cast<char *>(MapViewOfFile(this->mappingHandle, FILE_MAP_READ,
                                                             0, 0, 0));
        if (this->fileBuffer == nullptr) {
            throw Exception("Failed to read file.");
        }

        auto $1 = this->getCommitableDosHeader();
        auto $2 = this->getFormat();
        auto $3 = this->getCommitableSectionHeaders();
    } catch (Exception &) {
        this->destroy();
        throw;
    }
}
