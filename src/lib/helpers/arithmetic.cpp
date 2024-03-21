#include "helpers.h"
#include "exception.h"

template int findMinimum(int*, unsigned int);

template long int findMinimum(long int*, unsigned int);

template long long findMinimum(long long*, unsigned int);

template unsigned long int findMinimum(unsigned long int*, unsigned int);

template unsigned int findMinimum(unsigned int*, unsigned int);

template unsigned long long findMinimum(unsigned long long*, unsigned int);

template<typename T>
T findMinimum(T *elements, unsigned int size) {
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
}

template int findMaximum(int*, unsigned int);

template long int findMaximum(long int*, unsigned int);

template long long findMaximum(long long*, unsigned int);

template unsigned long int findMaximum(unsigned long int*, unsigned int);

template unsigned int findMaximum(unsigned int*, unsigned int);

template unsigned long long findMaximum(unsigned long long*, unsigned int);

template<typename T>
T findMaximum(T *elements, unsigned int size) {
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
}

template int minimumDivisible(int, unsigned int);

template long int minimumDivisible(long int, unsigned int);

template long long minimumDivisible(long long, unsigned int);

template unsigned long int minimumDivisible(unsigned long int, unsigned int);

template unsigned int minimumDivisible(unsigned int, unsigned int);

template unsigned long long minimumDivisible(unsigned long long, unsigned int);

template<typename T>
T minimumDivisible(T number, unsigned int divisor) {
    T modulo = number % divisor;
    if (modulo == 0) {
        return number;
    } else if (modulo < 0) {
        return number - modulo;
    } else {
        return number + divisor - modulo;
    }
}

template int findAbsolute(int);

template long int findAbsolute(long int);

template long long findAbsolute(long long);

template unsigned long int findAbsolute(unsigned long int);

template unsigned int findAbsolute(unsigned int);

template unsigned long long findAbsolute(unsigned long long);

template<typename T>
T findAbsolute(T number) {
    return number >= 0 ? number : -number;
}