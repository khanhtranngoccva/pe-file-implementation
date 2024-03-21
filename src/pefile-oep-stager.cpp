#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "exception.h"
#include "helpers.h"

int main(const int argc, const char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: pefile-oep-stager.exe [target-path]" << std::endl;
        exit(1);
    }

    const char *targetName = argv[1];
    std::cout << "STAGING OEP ON: " << targetName << std::endl;

    PE* pefile;
    try {
        pefile = new PE(targetName);
        unsigned long long oldEntryPoint;
        unsigned long long imageBase;
        if (pefile->getFormat() == IMAGE_FORMAT_PE32) {
            auto header = pefile->getCommitableNtHeaders32();
            oldEntryPoint = header->OptionalHeader.AddressOfEntryPoint;
            imageBase = header->OptionalHeader.ImageBase;
        } else {
            auto header = pefile->getCommitableNtHeaders64();
            oldEntryPoint = header->OptionalHeader.AddressOfEntryPoint;
            imageBase = header->OptionalHeader.ImageBase;
        }
        std::cout << "Old entry point [HEX]: " << hexify(oldEntryPoint) << std::endl;
        std::cout << "Old entry point: " << oldEntryPoint << std::endl;
        std::string line = "#define RESUME_POINT " + hexify(oldEntryPoint + imageBase) + std::string("\n");

        auto fileHandle = CreateFileA("oep-stager-header.h", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!fileHandle) {
            CloseHandle(fileHandle);
            throw Exception("Failed to open oep-stager-header.h");
        }

        auto result = WriteFile(fileHandle, line.c_str(), line.length(), nullptr, nullptr);
        if (!result) {
            CloseHandle(fileHandle);
            throw Exception("Failed to write to oep-stager-header.h");
        }

        pefile->destroy();
        free(pefile);
    } catch (Exception &e) {
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        pefile->destroy();
        free(pefile);
        return 1;
    }

    return 0;
}
