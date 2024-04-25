#include<iostream>
#include "../ara/crypto/helper/print.h"
#include "../ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h"
#include "../ara/crypto/private/common/mem_region.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;

int main()
{
    CryptoPP_SHA_256_HashFunctionCtx h;
    
    h.Start();

    std::string str = "ahmed mahmoud";
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    //std::uint8_t instr = 'w';
    
    ara::core::Result<void> res_update =  h.Update(instr);
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
    

    ara::core::Result<ara::core::Vector<ara::core::Byte>> res_finish = h.Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
        auto digest =  h.GetDigest();

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
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
    }
    

    return 0;
}