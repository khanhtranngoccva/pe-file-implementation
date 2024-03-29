#pragma once
#include <ctime>
#include <string>

std::string formatTime(time_t timestamp);

template<typename T>
std::string hexify(T i);

bool maskMatch(unsigned int input, unsigned int compare);
std::string boolStr(bool input);
std::string maskMatchStr(unsigned int input, unsigned int compare);

template<typename T>
T findMinimum(T *elements, unsigned int size);

template<typename T>
T findMaximum(T *elements, unsigned int size);

template<typename T>
T minimumDivisible(T number, unsigned int divisor);

template<typename T>
T findAbsolute(T number);

bool isFile(std::string& path);

bool isDirectory(std::string& path);