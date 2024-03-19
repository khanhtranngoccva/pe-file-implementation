#include <iomanip>
#include <ctime>
#include "helpers.h"
#include <sstream>
#include "exception.h"

#define MAX_TIME_DISPLAY_LENGTH 100

std::string formatTime(const time_t timestamp) {
    char output[MAX_TIME_DISPLAY_LENGTH + 1];
    tm curTime{};
    gmtime_s(&curTime, &timestamp);
    strftime(output, MAX_TIME_DISPLAY_LENGTH, "%Y/%m/%d %H:%M:%S UTC", &curTime);
    return output;
}

template std::string hexify(int);

template std::string hexify(unsigned long int);

template std::string hexify(unsigned int);

template std::string hexify(unsigned long long);

template<typename T>
std::string hexify(T i) {
    std::stringstream stream;
    stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::uppercase
            << std::hex << i;
    return stream.str();
}

bool maskMatch(unsigned int input, unsigned int compare) {
    return !!(input & compare);
}

std::string boolStr(bool input) {
    return input ? "true" : "false";
}

std::string maskMatchStr(unsigned int input, unsigned int compare) {
    return boolStr(maskMatch(input, compare));
}

template<typename T>
T find_minimum(T *elements, unsigned int size) {
    if (size == 0) {
        throw InvalidParametersException("Element array must be greater than 0.");
    }
    T curMin = elements[0];
    for (unsigned int i = 0; i < size; i++) {
        if (elements[i] < curMin) {
            curMin = elements[i];
        }
    }
    return curMin;
};

template<typename T>
T max(T *elements, unsigned int size) {
    if (size == 0) {
        throw InvalidParametersException("Element array must be greater than 0.");
    }
    T curMax = elements[0];
    for (unsigned int i = 0; i < size; i++) {
        if (elements[i] > curMax) {
            curMax = elements[i];
        }
    }
    return curMax;
};
