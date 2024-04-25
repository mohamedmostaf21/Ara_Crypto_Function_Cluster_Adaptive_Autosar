#include <iostream>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.h"

using namespace ara::crypto::cryp;
int main()
{
    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();
    
    CryptoPP_AES_SymmetricBlockCipherCtx myContext;
    
    CryptoPrimitiveId::Uptr myContextPrimitiveId = myContext.GetCryptoPrimitiveId();
    std::cout << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << myContextPrimitiveId->GetPrimitiveName() << std::endl;
    

    myContext.SetKey(*myKey);
    
    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    ara::core::Result<ara::core::Vector<ara::core::Byte>> _result = myContext.ProcessBlock(instr);
    if(_result.HasValue())
    {
        //std::cout << "--- sucess ---\n";
        // Convert digest to hexadecimal string
        std::stringstream ss;
        std::cout << "output: ";
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
    }
    
}