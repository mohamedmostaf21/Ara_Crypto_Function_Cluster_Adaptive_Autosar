#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "../ara/crypto/public/cryp/cryobj/cryptopp_hmac_sha_256_signature.h"
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

    auto hmac256Create = myProvider->CreateMessageAuthCodeCtx(HMAC_SHA_256_ALG_ID);

    if(!hmac256Create.HasValue())
    {
        std::cout << "Failed to Create HMAC 256 Context\n";
        return 0;
    }

    
    auto hmac256 = std::move(hmac256Create).Value();

    auto myKeyResult = myProvider->GenerateSymmetricKey(HMAC_SHA_256_ALG_ID,kAllowSignature);

    if(!myKeyResult.HasValue())
    {
        std::cout << "Failed to generate symmetric key\n";
        return 0;
    }

    auto myKey = std::move(myKeyResult).Value();

    hmac256->SetKey(*myKey);
    
    std::string str = "Hello There";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());


    auto _result_Start = hmac256->Start();
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

    auto _result_Update = hmac256->Update(instr);
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

    auto _result_Finish = hmac256->Finish();
    if(_result_Finish.HasValue())
    {
        std::cout<<"success Finish\n";

        auto digest =  hmac256->GetDigest();

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

    CryptoPP_HMAC_SHA256_Signature sign;

    CryptoPP::SecByteBlock digest(hmac256->GetDigest().Value().data(), hmac256->GetDigest().Value().size());



    sign.setValue(digest);

    if(hmac256->Check(sign).Value() == true)
    {
        std::cout<<"Verified\n";
    }
    else
    {
        std::cout<<"Not Verifiedr\n";
    }
}