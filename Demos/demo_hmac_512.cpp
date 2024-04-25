#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_hmac_sha_512_message_authn_code_ctx.h"
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

    auto hmac512Create = myProvider->CreateMessageAuthCodeCtx(HMAC_SHA_512_ALG_ID);

    if(!hmac512Create.HasValue())
    {
        std::cout << "Failed to Create HMAC 512 Context\n";
        return 0;
    }

    
    auto hmac512 = std::move(hmac512Create).Value();

    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();

    hmac512->SetKey(*myKey);
    
    std::string str = "Hello There";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());


    auto _result_Start = hmac512->Start();
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

    auto _result_Update = hmac512->Update(instr);
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

    auto _result_Finish = hmac512->Finish();
    if(_result_Finish.HasValue())
    {
        std::cout<<"success Finish\n";

        auto digest =  hmac512->GetDigest();

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