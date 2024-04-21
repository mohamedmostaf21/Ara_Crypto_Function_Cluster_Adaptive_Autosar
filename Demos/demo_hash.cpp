#include<iostream>
#include "../ara/crypto/public/cryp/cryptopp_crypto_provider.h"
#include "../ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h"
#include "../ara/crypto/private/common/mem_region.h"
#include "../ara/crypto/helper/print.h"
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/core/instance_specifier.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;


int main()
{
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


    /****************************************
    *          create sha-256 context       *
    ****************************************/
    auto res_create = myProvider->CreateHashFunctionCtx(1);
    if(!res_create.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_create.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    auto myContext = std::move(res_create).Value();
    

    /****************************************
    *      using Sha256HashFunctionCtx      * 
    ****************************************/  
    auto res_start = myContext->Start();
    if(res_start.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_start.Error();
        std::cout << error.Message() << std::endl;
        //return 0;
    }

    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    
    auto res_update =  myContext->Update(instr);
    if(res_update.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_update.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    
    auto res_finish = myContext->Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get hash value
        auto hashValue =  res_finish.Value();

        printHex(hashValue);
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
    }

    return 0;
}