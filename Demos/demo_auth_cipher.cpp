#include <iostream>
#include "../ara/crypto/public/cryp/cryptopp_auth_cipher_ctx.h"
#include "../ara/crypto/private/common/mem_region.h"
#include "../ara/core/result.h"
#include "../ara/crypto/helper/print.h"
#include "../ara/crypto/private/common/entry_point.h"
#include "../ara/core/instance_specifier.h"
#include <cryptopp/secblock.h>

using namespace ara::crypto::cryp;
using namespace ara::crypto::helper;
using namespace ara::core;
using namespace ara::crypto;

int main()
{

    std::cout << "---------------- Authentication Cipher Context Demo ------------------" << std::endl;
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
    *    using loaded crypto provider to generate symmetric key   *
    **************************************************************/
    auto res_genSymtKey = myProvider->GenerateSymmetricKey(AUTH_CIPHER_ALG_ID, kAllowKdfMaterialAnyUsage);
    if(!res_genSymtKey.HasValue())
    {
        std::cout << "failed to generate symmetric key\n";

        
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_genSymtKey.Error();
        std::cout << error.Message() << std::endl;

        return 0;
    }
    auto mySymmetricKey = std::move(res_genSymtKey).Value();

    /****************************************
    *       create auth_cipher context      *
    ****************************************/
    auto res_create = myProvider->CreateAuthCipherCtx(AUTH_CIPHER_ALG_ID);
    if(!res_create.HasValue())
    {
        std::cout << "--- error ---\n";
        ara::core::ErrorCode error = res_create.Error();
        std::cout << error.Message() << std::endl;
        return 0;
    }

    auto myContext = std::move(res_create).Value();

    CryptoPrimitiveId::Uptr myContextPrimitiveId = myContext->GetCryptoPrimitiveId();
    std::cout << "Primative ID: " << myContextPrimitiveId->GetPrimitiveId() << std::endl;
    std::cout << "Primative Name: " << myContextPrimitiveId->GetPrimitiveName() << std::endl;

    myContext->SetKey(*mySymmetricKey);

 
    // Check if the context is initialized
    bool initialized = myContext->IsInitialized();
    if (initialized) {
        std::cout << "Context is initialized." << std::endl;
    } else {
        std::cerr << "Context is not initialized." << std::endl;
    }


    std::cout << std::endl;

    std::string str = "Mohamed Mostafa Shaban";    
    ara::crypto::ReadOnlyMemRegion instr(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
    myContext->Start();

    ara::core::Result<void> res_update =  myContext->Update(instr);
    auto res_finish = myContext->Finish();
    
    //For Checking Only
    // ara::core::Vector<ara::core::Byte> res = {38, 56, 90};
    bool flag = myContext->VerifyTag({myContext->GetDigest().Value()});
    if(flag){
        std::cout << "Verify True" << std::endl;
    }else{
        std::cout << "Verify False" << std::endl;
    }
     std::cout << std::endl;
    auto resultDigest = myContext->GetDigest();
    if(resultDigest.HasValue()){
    
        const auto& processedData = resultDigest.Value();

        // Iterate over each byte in the processed data and print it
        std::cout << "Digest Value: ";
        for (const auto& byte : processedData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
    
     std::cout << std::endl;
    /****************************************
    *            create signature           *
    ****************************************/
    ara::crypto::ReadOnlyMemRegion data(reinterpret_cast<const std::uint8_t*>(resultDigest.Value().data()), resultDigest.Value().size() );
    auto result_create = myProvider->CreateSignature(SIGNATURE_CREATION_ALG_ID, data, *mySymmetricKey);

    auto mySignature = std::move(result_create).Value();
   
    auto signature = mySignature->GetDigestValue(); 
    std::cout << "Signature: ";
    for (const auto& byte : signature) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    auto check = myContext->Check(*mySignature);
    if(check){
        std::cout << "Check Signature Passed" << std::endl;
    }else{
        std::cout << "Check Signature Not Passed" << std::endl;
    }

    std::cout << std::endl;
    ara::core::Result<void> updateResult = myContext->UpdateAssociatedData(instr);
    if (updateResult.HasValue()) {
        std::cout << "Associated data updated successfully." << std::endl;
      
    } else {
        std::cerr << "Error updating associated data: " << std::endl;
    }
    std::cout << std::endl;
    std::cout << "Max Associated Data : "<< myContext->GetMaxAssociatedDataSize() << std::endl;
     std::cout << std::endl;
    auto transform = myContext->GetTransformation();
    if(transform.HasValue()){
        std::cout << "Current Transform : " << myContext->ToString(transform.Value()) << std::endl;
    }
    
    //Encryption

    ara::crypto::ReadOnlyMemRegion expectedTagData(reinterpret_cast<const std::uint8_t*>(resultDigest.Value().data()), resultDigest.Value().size());
    ara::core::Result<ara::core::Vector<ara::core::Byte> > result =  myContext->ProcessConfidentialData(instr, expectedTagData);

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

     std::cout << std::endl;
    //process same data 
   
    ara::core::Result<ara::core::Vector<ara::core::Byte> > resultSame =  myContext->ProcessConfidentialData(instr, expectedTagData);

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
        std::cerr << "Error processing confidential data. " << std::endl;
    }
     std::cout << std::endl;
    myContext->SetTransformation(CryptoTransform::kDecrypt);
    
    //Decryption
    ara::crypto::ReadOnlyMemRegion EncryptedData(reinterpret_cast<const std::uint8_t*>(result.Value().data()), result.Value().size());
    ara::core::Result<ara::core::Vector<ara::core::Byte> > resultDec =  myContext->ProcessConfidentialData(EncryptedData, expectedTagData);

    if (resultDec.HasValue()) {
        std::cout << "Confidential data processed successfully." << std::endl;
        const auto& processedData = resultDec.Value();
     
        // Convert processedData to a hexadecimal string
        std::stringstream hexStream;
        for (const auto& byte : processedData) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
      
        std::string plain = hex_to_string(hexStream.str());
        std::cout << "Processed Data Decrypted (plain): " << plain << std::endl;
    } else {
        std::cerr << "Error processing confidential data." << std::endl;
    }

     std::cout << std::endl;
    //Decryption 
    //process same data 
   
    ara::core::Result<ara::core::Vector<ara::core::Byte> > resultDecSame =  myContext->ProcessConfidentialData(EncryptedData, expectedTagData);

    if (resultDecSame.HasValue()) {
        std::cout << "Confidential data processed successfully." << std::endl;
        const auto& processedData = resultDecSame.Value();
     
        // Convert processedData to a hexadecimal string
        std::stringstream hexStream;
        for (const auto& byte : processedData) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
      
        std::string plain = hex_to_string(hexStream.str());
        std::cout << "Processed Data Decrypted (plain): " << plain << std::endl;
    } else {
        std::cerr << "Error processing confidential data." << std::endl;
    }



}