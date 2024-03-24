#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "Argument count: " << argc << std::endl;
    std::cout << "Argument pointer: " << argv << std::endl;
    for (int i = 0; i < argc; i++) {
        std::cout << argv[i] << std::endl;
    }
    std::cout << "Testing" << std::endl;
}