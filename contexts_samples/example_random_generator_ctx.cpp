#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_random_generator_ctx.h"
#include "../ara/crypto/private/common/mem_region.h"

using namespace ara::crypto::cryp;
int main()
{
    std::cout << "---------------- Random Generation Context Demo ------------------" << std::endl;
    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();
    
    Cryptopp_RandomGeneratorctx rn;
    
    CryptoPrimitiveId::Uptr myContextPrimitiveId = rn.GetCryptoPrimitiveId();
    std::cout << "Primative ID: " << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << "Primative Name: " << myContextPrimitiveId->GetPrimitiveName() << std::endl;
    
    rn.SetKey(*myKey);
    ara::core::Result< ara::core::Vector<ara::core::Byte> > result = rn.Generate(16);
    std::cout << "Random Number Generation:";
    for(int i = 0; i < result.Value().size(); i++)
    {
        std::cout << " " << std::hex << static_cast<int>(result.Value()[i]);
    }
    std::cout << std::endl;
    ara::crypto::ReadOnlyMemRegion mem;
    const std::uint8_t inputData[] = { 'E', 'n', 't', 'r', 'o', 'p', 'y', ' ', 'I', 'n', 'p', 'u', 't', ' ', 'E', 'x', 'a', 'm', 'p', 'l', 'e', '\0' };
    mem = ara::crypto::ReadOnlyMemRegion(inputData, sizeof(inputData) - 1); // -1 to exclude the null terminator

    // Output the data
    for (const auto& byte : mem) {
        std::cout << static_cast<char>(byte); // Assuming the data is printable ASCII characters
    }
    std::cout << std::endl;

    bool resultEntropy = rn.AddEntropy(mem);
    std::cout << "Can Entropy ? : " << std::boolalpha << resultEntropy << std::endl;
    if(resultEntropy)
    {
        result = rn.Generate(16);
        std::cout << "New Random Number Generation with added entropty:";
        for(int i = 0; i < result.Value().size(); i++)
        {
            std::cout << " " << std::hex << static_cast<int>(result.Value()[i]);
        }
        std::cout << std::endl;
    }

    ara::crypto::SeedData seedData;
    CryptoPP::byte seed[16];
    seedData.seed = seed;
    seedData.length = sizeof(seed);
    mem = ara::crypto::ReadOnlyMemRegion(seedData.seed, seedData.length);
    bool resultSeed = rn.Seed(mem);
    std::cout << "Can ReSeed ? : " << std::boolalpha << resultSeed << std::endl;
    if(resultSeed)
    {
        result = rn.Generate(16);
        std::cout << "New Random Number Generation with added Seed:";
        for(int i = 0; i < result.Value().size(); i++)
        {
            std::cout << " " << std::hex << (int)result.Value()[i];
        }
        std::cout << std::endl;
    }
    //ExtensionService::Uptr myService = rn.GetExtensionService();
    
    return 0;
}