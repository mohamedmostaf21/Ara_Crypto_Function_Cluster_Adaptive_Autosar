#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h"
#include "../ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.h"
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

    auto hash256Create = myProvider->CreateHashFunctionCtx(SHA_256_ALG_ID);

    if(!hash256Create.HasValue())
    {
        std::cout << "Failed to Create HMAC 256 Context\n";
        return 0;
    }

    
    auto hash256 = std::move(hash256Create).Value();

    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();

    
    std::string str = "Hello There";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());


    auto _result_Start = hash256->Start();
    if(_result_Start.HasValue())
    {
        std::cout<<"success Start\n";
    }
    else
    {
        std::cout<<"Error\n";
        ara::core::ErrorCode error = _result_Start.Error();
        std::cout << error.Message() << std::endl;
    }

    auto _result_Update = hash256->Update(instr);
    if(_result_Update.HasValue())
    {
        std::cout<<"success Update\n";
    }
    else
    {
        std::cout<<"Error\n";
        ara::core::ErrorCode error = _result_Update.Error();
        std::cout << error.Message() << std::endl;
    }

    auto _result_Finish = hash256->Finish();
    if(_result_Finish.HasValue())
    {
        std::cout<<"success Finish\n";

        auto digest =  hash256->GetDigest();

        if(digest.HasValue())
        {
            printHex(digest.Value());
        }
        else
        {
            std::cout<<"Error\n";
            ara::core::ErrorCode error = digest.Error();
            std::cout << error.Message() << std::endl;
        }
    }
    else
    {
        std::cout<<"Error\n";
        ara::core::ErrorCode error = _result_Finish.Error();
        std::cout << error.Message() << std::endl;
    }
}