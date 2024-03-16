#pragma once

#include <ctime>

std::string formatTime(time_t timestamp);

template<typename T>
std::string hexify(T i);

bool maskMatch(unsigned int input, unsigned int compare);
std::string boolStr(bool input);
std::string maskMatchStr(unsigned int input, unsigned int compare);

