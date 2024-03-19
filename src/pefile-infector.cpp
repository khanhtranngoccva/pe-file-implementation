#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "exception.h"

int main(const int argc, const char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: pefile-infector.exe [target-path] [source-path]" << std::endl;
        exit(1);
    }

    const char *targetName = argv[1];
    std::cout << "INFECTING: " << targetName << std::endl;

    try {
        auto pefile = PE(targetName);
        DWORD oldEntryPoint;
        if (pefile.getFormat() == IMAGE_FORMAT_PE32) {
            oldEntryPoint = pefile.getCommitableNtHeaders32()->OptionalHeader.AddressOfEntryPoint;
        } else {
            oldEntryPoint = pefile.getCommitableNtHeaders64()->OptionalHeader.AddressOfEntryPoint;
        }
        std::cout << "Old entry point: " << oldEntryPoint << std::endl;
    } catch (Exception &e) {
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    return 0;
}
