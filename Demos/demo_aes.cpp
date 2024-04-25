#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.h"
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

    auto aes_contextCreate = myProvider->CreateSymmetricBlockCipherCtx(1);

    if(!aes_contextCreate.HasValue())
    {
        std::cout << "Failed to Create AES Context\n";
        return 0;
    }

    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();
    
    auto aes_context = std::move(aes_contextCreate).Value();
    
    aes_context->SetKey(*myKey);
    
    std::string str = "Hello There";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());


    auto _result_encrypt = aes_context->ProcessBlock(instr);
    if(_result_encrypt.HasValue())
    {
        std::cout<<"success\n";

        auto encryptedData = _result_encrypt.Value();

        printHex(encryptedData);

        aes_context->SetKey(*myKey, ara::crypto::CryptoTransform::kDecrypt);

        auto _result_decrypt = aes_context->ProcessBlock(encryptedData);

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