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
        } else {
            auto header = pefile->getCommitableNtHeaders64();
            oldEntryPoint = header->OptionalHeader.AddressOfEntryPoint;
        }

        std::string dummyName("dummy");
        auto demoNewSectionHeader = pefile->pushNewSection(dummyName, 0, 0);
        // Takes advantage of deterministic section creation to predict the entry point of shellcode and make a relative jump.
        unsigned long long newEntryPoint = demoNewSectionHeader->VirtualAddress;
        std::cout << "Old entry point: " << oldEntryPoint << std::endl;
        std::cout << "New entry point: " << newEntryPoint << std::endl;

        auto line = std::to_string(newEntryPoint - oldEntryPoint);

        auto fileHandle = CreateFileA("reljump.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!fileHandle) {
            CloseHandle(fileHandle);
            throw Exception("Failed to open reljump.txt");
        }

        auto result = WriteFile(fileHandle, line.c_str(), line.length(), nullptr, nullptr);
        if (!result) {
            CloseHandle(fileHandle);
            throw Exception("Failed to write to reljump.txt");
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
