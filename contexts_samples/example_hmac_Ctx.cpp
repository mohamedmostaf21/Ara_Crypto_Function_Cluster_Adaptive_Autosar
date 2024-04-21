#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "../ara/crypto/public/cryp/cryobj/cryptopp_hmac_sha_256_signature.h"
#include "../ara/crypto/private/common/mem_region.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;

int main()
{
    CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx myContext;

    SymmetricKey::Uptrc myKey = CryptoPP_AES_SymmetricKey::createInstance();

    myContext.SetKey(*myKey);

    auto res_start = myContext.Start();
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
    //std::uint8_t instr = 'w';
    

    auto res_update =  myContext.Update(instr);
    if(res_update.HasValue())
    {
        std::cout << "--- sucess ---\n";
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_update.Error();
        std::cout << error.Message() << std::endl;
        //return 0;
    }


    auto res_finish = myContext.Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
      
        auto res_getDigest = myContext.GetDigest();
        if(res_getDigest.HasValue())
        {
            std::cout << "--- sucess ---\n";
            
            // get digest value
            auto digestValue = res_getDigest.Value();
            
            printHex(digestValue);
        }
        else
        {
            std::cout << "--- error ---\n";
            ara::core::ErrorCode error = res_getDigest.Error();
            std::cout << error.Message() << std::endl;
        }
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
    }
    
    return 0;
}