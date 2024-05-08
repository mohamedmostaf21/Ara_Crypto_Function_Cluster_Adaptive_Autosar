
#include "../ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;

int main()
{
    CryptoPP_SHA_256_HashFunctionCtx myContext;
    
    // ara::crypto::ReadOnlyMemRegion IV;
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
        return 0;
    }
    
    auto res_finish = myContext.Finish();
    if(res_finish.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get hash value
        auto hashValue =  res_finish.Value();

        printHex(hashValue);
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_finish.Error();
        std::cout << error.Message() << std::endl;
    }
    return 0;
}
