# ElyXor

use:

#include <iostream>
#include "xor.h"
int main() {
    auto encrypted = elyXor("Hello World!");
    std::cout << encrypted.decrypt() << std::endl;

    std::cout << elyXor("Test String").decrypt() << std::endl;

    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
