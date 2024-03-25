#include <string>
#include "exception.h"

unsigned short stMode(std::string& path) {
    struct stat s;
    if (stat(path.c_str(), &s)) {
        throw Exception(std::string("Unable to stat file") + path);
    }
    return s.st_mode;
}


bool isFile(std::string& path) {
    return !!(stMode(path) & S_IFREG);
}

bool isDirectory(std::string& path) {
    return !!(stMode(path) & S_IFDIR);
}
