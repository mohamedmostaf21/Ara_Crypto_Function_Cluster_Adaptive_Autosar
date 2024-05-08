#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cryptopp/hmac.h>

#define std_stringstream 1
#define CryptoPP_StringSource_FileSink 2
#define CryptoPP_StringSource_StringSink 3
#define ALL_WAYS 4
#define PRINTING_WAY ALL_WAYS


bool verifyHMAC(const std::string& message, const std::string& key, const std::string& receivedHMAC)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    CryptoPP::SecByteBlock digest(CryptoPP::SHA256::DIGESTSIZE);

    hmac.SetKey((const CryptoPP::byte*)key.data(), key.size());
    hmac.Update((const CryptoPP::byte*)message.data(), message.size());
    hmac.Final(digest);

    std::string computedHMAC;
    CryptoPP::StringSource(digest, digest.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(computedHMAC)
        )
    );

    return computedHMAC == receivedHMAC;
}

int main()
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    CryptoPP::SecByteBlock digest(CryptoPP::SHA256::DIGESTSIZE);

    const std::string message = "Hello, HMAC!";
    const std::string key = "SecretKey";
    
    hmac.Restart();
    hmac.SetKey((const CryptoPP::byte*)key.data(), key.size());
    hmac.Update((const CryptoPP::byte*)message.data(), message.size());
    hmac.Final(digest);

#if(PRINTING_WAY == std_stringstream || PRINTING_WAY == ALL_WAYS)
    std::vector<uint8_t> result;
    for (const auto& byte : digest)
    {
        result.push_back(static_cast<uint8_t>(byte));
    }
    // Convert digest to hexadecimal string
    std::stringstream ss;
    for (const auto& byte : result) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    // Print the hexadecimal digest
    std::cout << "HMAC-SHA256 digest: ";
    std::cout << ss.str() << std::endl;
    std::cout << "-------------\n";
#endif
    
#if(PRINTING_WAY == CryptoPP_StringSource || PRINTING_WAY == ALL_WAYS)
    std::cout << "HMAC-SHA256 digest: ";
    CryptoPP::StringSource(digest, digest.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::FileSink(std::cout)
        )
    );
    std::cout << "\n-------------\n";
#endif

#if(PRINTING_WAY == CryptoPP_StringSource || PRINTING_WAY == ALL_WAYS)
    std::string computedHMAC;
    CryptoPP::StringSource(digest, digest.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(computedHMAC)
        )
    );
    std::cout << "HMAC-SHA256 digest: ";
    std::cout << computedHMAC << std::endl;
#endif

    // Simulate sending the message and computed HMAC to the receiver
    std::string receivedHMAC = computedHMAC;

    // Verify the data at the receiver
    bool dataVerified = verifyHMAC(message, key, receivedHMAC);
    if (dataVerified) {
        std::cout << "Data verified successfully." << std::endl;
    } else {
        std::cout << "Data verification failed." << std::endl;
    }
    return 0;
}