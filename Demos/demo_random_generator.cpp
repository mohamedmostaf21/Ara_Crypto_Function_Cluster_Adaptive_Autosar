#include <iostream>
#include "../ara/crypto/private/common/mem_region.h"
#include "../ara/core/result.h"
#include "../ara/crypto/helper/print.h"
#include "../ara/crypto/private/common/entry_point.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;
int main()
{
    std::cout << "---------------- Random Generation Context Demo ------------------" << std::endl;
    /****************************************
    *          load a crypto provider       *
    ****************************************/
    InstanceSpecifier specifier("cryptopp");
    auto myProvider = LoadCryptoProvider(specifier);
    if(myProvider == nullptr)
    {
        std::cout << "failed to load crypto provider\n";
        return 0;
    }

    

    /**************************************************************
    *    using loaded crypto provider to generate symmetric key   *
    **************************************************************/
    auto res_genSymtKey = myProvider->GenerateSymmetricKey(RANDOM_GENERATOR_ALG_ID, kAllowKdfMaterialAnyUsage);
    if(!res_genSymtKey.HasValue())
    {
        std::cout << "failed to generate symmetric key\n";

        
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_genSymtKey.Error();
        std::cout << error.Message() << std::endl;

        return 0;
    }
    auto mySymmetricKey = std::move(res_genSymtKey).Value();

    /****************************************
    *       create random ctx context      *
    ****************************************/
    auto res_create = myProvider->CreateRandomGeneratorCtx(RANDOM_GENERATOR_ALG_ID);
    if(!res_create.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_create.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    auto myContext = std::move(res_create).Value();

    
    CryptoPrimitiveId::Uptr myContextPrimitiveId = myContext->GetCryptoPrimitiveId();
    std::cout << "Primative ID: " << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << "Primative Name: " << myContextPrimitiveId->GetPrimitiveName() << std::endl;
    
    myContext->SetKey(*mySymmetricKey);
    ara::core::Result< ara::core::Vector<ara::core::Byte> > result = myContext->Generate(16);
    std::cout << "Random Number Generation:";
    for(int i = 0; i < result.Value().size(); i++)
    {
        std::cout << " " << std::hex << static_cast<int>(result.Value()[i]);
    }
    std::cout << std::endl;



    std::string inputData = "Entropy Input Example";
    ara::crypto::ReadOnlyMemRegion mem(reinterpret_cast<const std::uint8_t*>(inputData.data()), inputData.size()); 

    // Output the data
    for (const auto& byte : mem) {
        std::cout << static_cast<char>(byte); // Assuming the data is printable ASCII characters
    }
    std::cout << std::endl;

    bool resultEntropy = myContext->AddEntropy(mem);
    std::cout << "Can Entropy ? : " << std::boolalpha << resultEntropy << std::endl;
    if(resultEntropy)
    {
        result = myContext->Generate(16);
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
    bool resultSeed = myContext->Seed(mem);
    std::cout << "Can ReSeed ? : " << std::boolalpha << resultSeed << std::endl;
    if(resultSeed)
    {
        result = myContext->Generate(16);
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