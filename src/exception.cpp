//
// Created by khanh on 3/16/2024.
//

#include "exception.h"
#include <cstring>

Exception::Exception(const char *message) {
    // Copy message to a customized pointer.
    const unsigned long buflen = strlen(message) + 1;
    this->message = static_cast<char *>(calloc(buflen, sizeof(char)));
    strcpy(this->message, message);
}

void Exception::destroy() const {
    free(this->message);
}

[[nodiscard]] const char* Exception::what() const noexcept {
    return this->message;
}

Exception::Exception(const std::string &message) {
    const auto buf = message.c_str();
    const unsigned long buflen = strlen(buf) + 1;
    this->message = static_cast<char *>(calloc(buflen, sizeof(char)));
    strcpy(this->message, buf);
}