#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;

int main()
{
    /************************************************************
    *                   EncryptorPublicCtx                      *
    ************************************************************/

    PublicKey::Uptrc myPublicKey = CryptoPP_RSA_2046_PublicKey::createInstance();

    CryptoPP_RSA_EncryptorPublicCtx myEncryptorPublicCtx;
    
    myEncryptorPublicCtx.SetKey(*myPublicKey);
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    auto _result = myEncryptorPublicCtx.ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get encrypted data
        auto encryptedDataVector = _result.Value();
        
        printHex(encryptedDataVector);  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    /************************************************************
    *                   DecryptorPrivateCtx                     *
    ************************************************************/
   
    PrivateKey::Uptrc myPrivateKey = CryptoPP_RSA_2046_PrivateKey::createInstance();
        
    CryptoPP_RSA_DecryptorPrivateCtx myDecryptorPrivateCtx;
    
    myDecryptorPrivateCtx.SetKey(*myPrivateKey);
    
    // get encrypted data
    auto encryptedDataVector = _result.Value();

    auto _result_decryptorPrivateCtx = myDecryptorPrivateCtx.ProcessBlock(encryptedDataVector);
    if(_result_decryptorPrivateCtx.HasValue())
    {
        std::cout << "--- sucess ---\n";

        // get decrypted data
        auto decryptedDataVector = _result_decryptorPrivateCtx.Value();

        printVector(decryptedDataVector, "recovered text: ");
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result_decryptorPrivateCtx.Error();
        std::cout << error.Message() << std::endl;
    }  
    return 0;
}