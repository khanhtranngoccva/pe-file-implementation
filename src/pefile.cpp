#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "exception.h"

int main(const int argc, const char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: pefile.exe [path]" << std::endl;
        exit(1);
    }

    const char *fileName = argv[1];
    std::cout << "Analyzing: " << fileName << std::endl;

    try {
        auto pefile = PE(fileName);
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayNtFileHeader();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayNtOptionalHeader();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displaySections();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayImports();
        std::cout << std::string(20, '-') << std::endl;
        pefile.displayExports();
        pefile.destroy();
    } catch (Exception &e) {
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    return 0;
}
