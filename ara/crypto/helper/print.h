#ifndef PRINT_H
#define PRINT_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <span>
#include <cstdint>

namespace ara
{
    namespace crypto
    {
        namespace helper
        {
            void printHex(const std::string& data, std::string description = "") 
            {
                std::cout << description;
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << ss.str() << std::endl;
            }

            void printHex(const std::vector<unsigned char>& data, std::string description = "")
            {
                std::cout << description;
                std::stringstream ss;
                for (const auto& byte : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::cout << ss.str() << std::endl;
            }

            void printHex(const std::span<const std::uint8_t>& data, std::string description = "") 
            {
                std::cout << description;
                for (const auto& byte : data) {
                    printf("%02x", byte);
                }
                std::cout << std::endl;
            }

            void printVector(const std::vector<unsigned char>& vec, std::string description = "") 
            {
                std::cout << description;
                for (const auto& elem : vec) {
                    std::cout << elem; // Print the character
                }
                std::cout << "\n";
            }   

            void printVector(std::string description, const std::vector<unsigned char>& vec) 
            {
                std::cout << description;
                for (const auto& elem : vec) {
                    std::cout << elem; // Print the character
                }
                std::cout << "\n";
            }    
            std::string hex_to_string(const std::string& hex) {
                std::string newString;
                for (std::size_t i = 0; i < hex.length(); i += 2) {
                    std::string byte = hex.substr(i, 2);
                    char chr = static_cast<char>(std::stoi(byte, nullptr, 16));
                    newString.push_back(chr);
                }
                return newString;
            }      
       }
    }
}

#endif