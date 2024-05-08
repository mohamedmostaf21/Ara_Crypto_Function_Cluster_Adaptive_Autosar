#include <iostream>
#include <stdlib.h>
#include "../ara/crypto/public/cryp/cryobj/cryptopp_aes_128_symmetric_key.h"
#include "../ara/crypto/public/cryp/cryptopp_auth_cipher_ctx.h"
#include "../ara/crypto/private/common/mem_region.h"
#include "../ara/core/result.h"
#include "../ara/crypto/helper/print.h"
using namespace ara::crypto::cryp;

int main()
{
    std::cout << "---------------- Authentication Cipher Context Demo ------------------" << std::endl;
    SymmetricKey::Uptrc myKey = CryptoPP_AES_128_SymmetricKey::createInstance();
    Cryptopp_AuthCipherCtx authCtx;
    CryptoPrimitiveId::Uptr myContextPrimitiveId = authCtx.GetCryptoPrimitiveId();
    std::cout << "Primative ID: " << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << "Primative Name: " << myContextPrimitiveId->GetPrimitiveName() << std::endl;

    authCtx.SetKey(*myKey);
    
 
    // Check if the context is initialized
    bool initialized = authCtx.IsInitialized();
    if (initialized) {
        std::cout << "Context is initialized." << std::endl;
    } else {
        std::cerr << "Context is not initialized." << std::endl;
    }

    std::string str = "Mohamed Mostafa Shaban";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    authCtx.Start();

    ara::core::Result<void> res_update =  authCtx.Update(instr);
    auto res_finish = authCtx.Finish();
    
    //For Checking Only
    // ara::core::Vector<ara::core::Byte> res = {38, 56, 90};
    bool flag = authCtx.VerifyTag({authCtx.GetDigest().Value()});
    if(flag){
        std::cout << "Verify True" << std::endl;
    }else{
        std::cout << "Verify False" << std::endl;
    }
    
    auto resultDigest = authCtx.GetDigest();
    if(resultDigest.HasValue()){
    
        const auto& processedData = resultDigest.Value();

        // Iterate over each byte in the processed data and print it
        std::cout << "Digest Value: ";
        for (const auto& byte : processedData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
    

 

    // CryptoPP_HMAC_SHA256_Signature sign;
    // sign.setValue(authCtx.digest);
    // auto signature = sign.GetDigestValue(); 
    // std::cout << "Signature: ";
    // for (const auto& byte : signature) {
    //         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << std::endl;

    // auto check = authCtx.Check(sign);
    // if(check){
    //     std::cout << "Check Signature Passed" << std::endl;
    // }else{
    //     std::cout << "Check Signature Not Passed" << std::endl;
    // }


    ara::core::Result<void> updateResult = authCtx.UpdateAssociatedData(instr);
    if (updateResult.HasValue()) {
        std::cout << "Associated data updated successfully." << std::endl;
      
    } else {
        std::cerr << "Error updating associated data: " << std::endl;
    }

    std::cout << "Max Associated Data : "<< authCtx.GetMaxAssociatedDataSize() << std::endl;

    auto transform = authCtx.GetTransformation();
    if(transform.HasValue()){
        std::cout << "Current Transform : " << authCtx.ToString(transform.Value()) << std::endl;
    }

    ara::crypto::ReadOnlyMemRegion expectedTagData(reinterpret_cast<const std::uint8_t*>(resultDigest.Value().data()), resultDigest.Value().size());
    ara::core::Result<ara::core::Vector<ara::core::Byte> > result =  authCtx.ProcessConfidentialData(instr, expectedTagData);

    if (result.HasValue()) {
        std::cout << "Confidential data processed successfully." << std::endl;
        const auto& processedData = result.Value();

        // Iterate over each byte in the processed data and print it
        std::cout << "Processed Data: ";
        for (const auto& byte : processedData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
 
    } else {
        std::cerr << "Error processing confidential data: " << std::endl;
    }

    //process same data
   
    ara::core::Result<ara::core::Vector<ara::core::Byte> > resultSame =  authCtx.ProcessConfidentialData(instr, expectedTagData);

    if (resultSame.HasValue()) {
        std::cout << "Confidential data processed successfully." << std::endl;
        const auto& processedData = resultSame.Value();

        // Iterate over each byte in the processed data and print it
        std::cout << "Processed Data: ";
        for (const auto& byte : processedData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
 
    } else {
        std::cerr << "Error processing confidential data: " << std::endl;
    }



}