
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;

#define example_string 1
#define example_vector 2
#define example example_string

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

    /**************************************************************
    *    using loaded crypto provider to generate private key     *
    **************************************************************/
    auto res_genPrKey = myProvider->GeneratePrivateKey(ECDSA_SHA_256_ALG_ID,kAllowSignature);
    if(!res_genPrKey.HasValue())
    {
        std::cout << "failed to generate private key\n";
        return 0;
    }
    auto myPrivateKey = std::move(res_genPrKey).Value();


    /**************************************************************
    *    getting public key from private key object               *
    **************************************************************/
    auto res_getPkKey = myPrivateKey->GetPublicKey();
    if(!res_getPkKey.HasValue())
    {
        std::cout << "failed to get public key\n";
        return 0;
    }
    auto myPublicKey = std::move(res_getPkKey).Value();


    /****************************************
    *          create ecdsa contexts        *
    ****************************************/
    auto res_createSigEncodePrivateCtx = myProvider->CreateSigEncodePrivateCtx(ECDSA_SHA_256_ALG_ID);
    auto res_createMsgRecoveryPublicCtx = myProvider->CreateMsgRecoveryPublicCtx(ECDSA_SHA_256_ALG_ID);

    if(!res_createSigEncodePrivateCtx.HasValue() && !res_createMsgRecoveryPublicCtx.HasValue())
    {
        std::cout << "failed to create ecdsa contexts\n";
        return 0;
    }
    
    auto mySigEncodePrivateCtx = std::move(res_createSigEncodePrivateCtx).Value();
    auto myMsgRecoveryPublicCtx = std::move(res_createMsgRecoveryPublicCtx).Value();


    /****************************************
    *        using SigEncodePrivateCtx      *
    ****************************************/
    mySigEncodePrivateCtx->SetKey(*myPrivateKey);

#if(example == example_string)
    std::string str = "ahmed mahmoud";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
#elif(example == example_vector)
    std::vector<uint8_t> instr = {1,2,3,4,5,6,7,8};
#endif

    auto _result = mySigEncodePrivateCtx->SignAndEncode(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get messagePlusSignature
        auto messagePlusSignature = _result.Value();
        
        printHex(instr, "Message: ");                 
        printHex(messagePlusSignature, "SignedMessage: ");  
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }
    std::cout << "------------------------------\n";



    /****************************************
    *       using  MsgRecoveryPublicCtx     *
    ****************************************/  
    myMsgRecoveryPublicCtx->SetKey(*myPublicKey);
    
    // get messagePlusSignature
    auto messagePlusSignature = _result.Value();

    //messagePlusSignature[0] = '0';

    auto _result2 = myMsgRecoveryPublicCtx->DecodeAndVerify(messagePlusSignature);   
    if(_result2.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get recoveryMessage
        auto recoveryMessage = _result2.Value();

#if(example == example_string)       
        printVector(recoveryMessage, "Verified Message: ");
#endif
        printHex(recoveryMessage, "Verified Message: ");  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result2.Error();
        std::cout << error.Message() << std::endl;
    }

    return 0;
}
