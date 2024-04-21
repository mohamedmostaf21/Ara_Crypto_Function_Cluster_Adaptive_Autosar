#include "../ara/crypto/public/cryp/cryobj/cryptopp_ecdsa_public_key.h"
#include "../ara/crypto/public/cryp/cryptopp_ecdsa_sig_encode_private_ctx.h"
#include "../ara/crypto/public/cryp/cryobj/cryptopp_ecdsa_public_key.h"
#include "../ara/crypto/public/cryp/cryptopp_ecdsa_msg_recovery_public_ctx.h"
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


    /****************************************
    *          load keys (not autosar)      *
    ****************************************/
    PrivateKey::Uptrc myPrivateKey = CryptoPP_ECDSA_PrivateKey::createInstance();
    PublicKey::Uptrc myPublicKey = CryptoPP_ECDSA_PublicKey::createInstance();


    /****************************************
    *          create ecdsa contexts        *
    ****************************************/
    auto res_createSigEncodePrivateCtx = myProvider->CreateSigEncodePrivateCtx(1);
    auto res_createMsgRecoveryPublicCtx = myProvider->CreateMsgRecoveryPublicCtx(1);

    if(!res_createSigEncodePrivateCtx.HasValue() && !res_createMsgRecoveryPublicCtx.HasValue())
    {
        std::cout << "failed two create ecdsa contexts\n";
        return 0;
    }
    
    auto mySigEncodePrivateCtx = std::move(res_createSigEncodePrivateCtx).Value();
    auto myMsgRecoveryPublicCtx = std::move(res_createMsgRecoveryPublicCtx).Value();


    /****************************************
    *        using SigEncodePrivateCtx      *
    ****************************************/

    mySigEncodePrivateCtx->SetKey(*myPrivateKey);
    
    std::string str = "ahmed mahmoud";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    auto _result = mySigEncodePrivateCtx->SignAndEncode(instr);
    if(_result.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get messagePlusSignature
        auto messagePlusSignature = _result.Value();
        
        printHex(str);                   // string
        printHex(messagePlusSignature);  // vector
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
        
        printVector("recovery message: ",recoveryMessage);
        
        printHex(recoveryMessage);  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result2.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }


    return 0;
}