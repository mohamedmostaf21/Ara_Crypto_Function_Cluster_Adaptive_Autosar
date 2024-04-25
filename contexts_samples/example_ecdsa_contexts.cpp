#include "../ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_sig_encode_private_ctx.h"
#include "../ara/crypto/public/cryp/cryptopp_ecdsa_sha_256_msg_recovery_public_ctx.h"
#include "../ara/crypto/helper/print.h"

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;

int main()
{
    /************************************************************
    *                   SigEncodePrivateCtx                     *
    ************************************************************/

    PrivateKey::Uptrc myPrivateKey = CryptoPP_ECDSA_PrivateKey::createInstance();

    CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx mySigEncodePrivateCtx;
    
    mySigEncodePrivateCtx.SetKey(*myPrivateKey);
    
    std::string str = "ahmed mahmoud";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());

    auto _result = mySigEncodePrivateCtx.SignAndEncode(instr);
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

    /************************************************************
    *                   MsgRecoveryPublicCtx                    *
    ************************************************************/
    CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx myMsgRecoveryPublicCtx;

    PublicKey::Uptrc myPublicKey = CryptoPP_ECDSA_SHA_256_PublicKey::createInstance();
    
    myMsgRecoveryPublicCtx.SetKey(*myPublicKey);
    
    // get messagePlusSignature
    auto messagePlusSignature = _result.Value();

    //messagePlusSignature[0] = '0';

    auto _result2 = myMsgRecoveryPublicCtx.DecodeAndVerify(messagePlusSignature);   
    if(_result2.HasValue())
    {
        std::cout << "--- sucess ---\n";
        
        // get recoveryMessage
        auto recoveryMessage = _result2.Value();
        
        printVector(recoveryMessage, "recovery message: ");
        
        printHex(recoveryMessage);  // vector
    }
    else
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = _result2.Error();
        std::cout << error.Message() << std::endl;
    }
    return 0;
}