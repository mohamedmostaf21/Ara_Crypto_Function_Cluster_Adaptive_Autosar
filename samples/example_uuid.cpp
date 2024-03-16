#include <iostream>
#include "../ara/crypto/private/common/uuid.h"

int main() {
    ara::crypto::Uuid uuid1{789, 789};
    ara::crypto::Uuid uuid2{123, 789};

    // Using the comparison operators
    if (uuid1 == uuid2) {
        std::cout << "uuid1 is equal to uuid2" << std::endl;
    } 
    else if (uuid1 < uuid2) {
        std::cout << "uuid1 is less than uuid2" << std::endl;
    } 
    else {
        std::cout << "uuid1 is greater than uuid2" << std::endl;
    }

    return 0;
}
