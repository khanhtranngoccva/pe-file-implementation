#pragma once

#include <string>
#include <exception>

class Exception : public std::exception {
    char *message;
public:
    explicit Exception(const char *message);
    void destroy() const;
    const char *what() const noexcept override;
    explicit Exception(const std::string &message);
};

class InvalidVirtualAddressException : public Exception {
public:
    explicit InvalidVirtualAddressException(const char *message) : Exception(message) {
    }
};

class InvalidPeFormatException : public Exception {
public:
    explicit InvalidPeFormatException(const char *message) : Exception(message) {
    }
};

class InvalidNtHeaderException : public Exception {
public:
    explicit InvalidNtHeaderException(const char *message) : Exception(message) {
    }
};

class InvalidDosHeaderException : public Exception {
public:
    explicit InvalidDosHeaderException(const char *message) : Exception(message) {
    }
};

class InvalidParametersException : public Exception {
public:
    explicit InvalidParametersException(const char *message) : Exception(message) {
    }
};