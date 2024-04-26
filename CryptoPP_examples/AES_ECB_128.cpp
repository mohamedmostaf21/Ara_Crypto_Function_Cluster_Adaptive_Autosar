#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>


#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <sstream>
#include <iomanip>

int main()
{
    // Key and plaintext
    std::string key = "0123456789abcdef";
    std::string plaintext = "ahmed mahmoud";


// Padding the plaintext to be a multiple of the block size
    size_t blockSize = CryptoPP::AES::BLOCKSIZE;
    size_t paddedSize = (plaintext.size() / blockSize + 1) * blockSize;
    std::string paddedPlaintext = plaintext;
    paddedPlaintext.resize(paddedSize, ' ');


    // Convert key and plaintext to Crypto++ format
    CryptoPP::SecByteBlock keyBytes((const unsigned char*)key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock ciphertext(keyBytes.size());
    CryptoPP::SecByteBlock recoveredtext(keyBytes.size());

    // Encryption using ECB mode
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(keyBytes, keyBytes.size());

    // Encrypt plaintext directly into ciphertext
    //e.ProcessData(ciphertext, (const CryptoPP::byte*)plaintext.data(), plaintext.size());
    e.ProcessData(ciphertext, (const CryptoPP::byte*)paddedPlaintext.data(), paddedPlaintext.size());
/***************************************/
    // Print ciphertext
    std::string computedCipher;
    CryptoPP::StringSource(ciphertext, ciphertext.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(computedCipher)
        )
    );
    std::cout << "cipher: ";
    std::cout << computedCipher << std::endl;
/***************************************/

    // Decryption using ECB mode
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(keyBytes, keyBytes.size());

    // Encrypt plaintext directly into ciphertext
    d.ProcessData(recoveredtext, ciphertext.data(), ciphertext.size());

/***************************************/
    // Print recoveredText
    std::string Recovered;
    CryptoPP::StringSource(recoveredtext, recoveredtext.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(Recovered)
        )
    );
    std::cout << "Recovered: ";
    std::cout << Recovered << std::endl;
/***************************************/


    return 0;
}
