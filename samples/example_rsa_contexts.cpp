#include <iostream>
#include <iomanip> // Include the header file for setfill
#include <sstream>
#include <string>

#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_public_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h"

#include "../ara/crypto/public/cryp/cryobj/cryptopp_rsa_private_key.h"
#include "../ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h"


using namespace ara::crypto::cryp;
int main()
{
    /************************************************************
    *                   EncryptorPublicCtx                      *
    ************************************************************/

    PublicKey::Uptrc myPublicKey = CryptoPP_RSA_PublicKey::createInstance();

    CryptoPP_RSA_EncryptorPublicCtx myEncryptorPublicCtx;

    CryptoPrimitiveId::Uptr myContextPrimitiveId = myEncryptorPublicCtx.GetCryptoPrimitiveId();
    std::cout << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << myContextPrimitiveId->GetPrimitiveName() << std::endl;
    
    myEncryptorPublicCtx.SetKey(*myPublicKey);
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    ara::core::Result<ara::core::Vector<ara::core::Byte>> _result = myEncryptorPublicCtx.ProcessBlock(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        // Convert digest to hexadecimal string
        std::stringstream ss;
        std::cout << "encryted text: ";
        for (const auto& byte : _result.Value()) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        // Print the hexadecimal digest
        std::cout << ss.str() << std::endl;
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
   
    PrivateKey::Uptrc myPrivateKey = CryptoPP_RSA_PrivateKey::createInstance();
        
    CryptoPP_RSA_DecryptorPrivateCtx myDecryptorPrivateCtx;
    
    myDecryptorPrivateCtx.SetKey(*myPrivateKey);
    
    ara::crypto::ReadOnlyMemRegion instr_d(reinterpret_cast<const std::uint8_t*>(_result.Value().data()), _result.Value().size());

    ara::core::Result<ara::core::Vector<ara::core::Byte>> _result2 = myDecryptorPrivateCtx.ProcessBlock(instr_d);
    if(_result2.HasValue())
    {
        ara::core::Vector<ara::core::Byte> recVector = _result2.Value();
        std::cout << "--- sucess ---\n";
        std::string recover(recVector.begin(), recVector.end());
        std::cout << "recovered text: " << recover << std::endl;
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result2.Error();
        std::cout << error.Message() << std::endl;
    }
        

    return 0;
}