#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_128_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_chacha_stream_cipher_ctx.h"
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

    auto chacha_ctxCreate = myProvider->CreateStreamCipherCtx(CHA_CHA_ALG_ID);

    if(!chacha_ctxCreate.HasValue())
    {
        std::cout << "Failed to Create CHA CHA Context\n";
        return 0;
    }

    auto myKeyResult = myProvider->GenerateSymmetricKey(CHA_CHA_ALG_ID,kAllowKdfMaterialAnyUsage);

    if(!myKeyResult.HasValue())
    {
        std::cout << "Failed to generate symmetric key\n";
        return 0;
    }

    auto myKey = std::move(myKeyResult).Value();
    
    auto chacha_ctx = std::move(chacha_ctxCreate).Value();
    
    chacha_ctx->SetKey(*myKey);

    chacha_ctx->Start();


    
    std::string str = "Hello";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    

    auto _result_encrypt = chacha_ctx->ProcessBytes(instr);

    str = " There";
    ara::crypto::ReadOnlyMemRegion instr1(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    _result_encrypt = chacha_ctx->ProcessBytes(instr1);

    str = " World!!";
    ara::crypto::ReadOnlyMemRegion instr2(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    _result_encrypt = chacha_ctx->FinishBytes(instr2);

    if(_result_encrypt.HasValue())
    {
        std::cout<<"success\n";

        auto encryptedData = _result_encrypt.Value();

        printHex(encryptedData);

        chacha_ctx->SetKey(*myKey, ara::crypto::CryptoTransform::kDecrypt);

        auto _result_decrypt = chacha_ctx->ProcessBlocks(encryptedData);

        if(_result_decrypt.HasValue())
        {
            std::cout<<"success\n";

            auto decryptedData = _result_decrypt.Value();

            printHex(decryptedData);

            printVector("Decrypted Data : ", decryptedData);

        }
    }
    else
    {
        std::cout<<"Error\n";
        ara::core::ErrorCode error = _result_encrypt.Error();
        std::cout << error.Message() << std::endl;
    }
}