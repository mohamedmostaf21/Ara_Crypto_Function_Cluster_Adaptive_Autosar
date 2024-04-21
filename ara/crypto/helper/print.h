#ifndef PRINT_H
#define PRINT_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>


namespace ara
{
    namespace crypto
    {
        namespace helper
        {
            void printHex(const std::string& data) 
            {
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << "Hexadecimal representation: " << ss.str() << std::endl;
            }

            void printHex(const std::vector<unsigned char>& data)
            {
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << "Hexadecimal representation: " << ss.str() << std::endl;
            }

            void printVector(std::string description, const std::vector<unsigned char>& vec) 
            {
                std::cout << description;
                for (const auto& elem : vec) {
                    std::cout << elem; // Print the character
                }
                std::cout << "\n";
            }
       }
    }
}

#endif