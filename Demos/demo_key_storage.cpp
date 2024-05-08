
#include "../ara/crypto/private/common/entry_point.h"

#include <iostream>

// namespaces

using namespace  ara::crypto::keys;
using namespace  ara::crypto;

int main() {
    /****************************************************************************************************
    *    using loaded crypto provider to generate Symmetric key and Save it by key storage provider     *
    *****************************************************************************************************/
    //Load Crypto_Provider
    ara::core::InstanceSpecifier crypto_spec("cryptopp");
    auto myProvider_crypto = LoadCryptoProvider (crypto_spec);  
    
    //Generate Key
    auto result = myProvider_crypto->GenerateSymmetricKey(AES_ECB_128_ALG_ID,kAllowKdfMaterialAnyUsage);
    if(!result.HasValue())
    {
        std::cout<<"error\n";
    }
    auto my_SymmetricKey=std::move(result).Value();

    //Load Key_Storage_Provider
    auto myProvider_key_storage = LoadKeyStorageProvider();
    //Save Key

    //Load Key Slot
    ara::core::InstanceSpecifier AES("aes_symmetric_key_1");
    keys::KeySlot::Uptr symmetric_key_Slot = myProvider_key_storage->LoadKeySlot(AES).Value();
    std::cout<<"BEGAIN" << std::endl;
    symmetric_key_Slot->printData();
    std::cout<<"END" << std::endl;
   
    //Open Key Slot
    CryptoPP_IOInterface::Uptr io_symmetric = symmetric_key_Slot->Open(false, true).Value();
    std::cout << "Path = " << io_symmetric->IsValid() << std::endl;
    my_SymmetricKey->Save(*io_symmetric);

    std::cout << std::endl;
    /**************************************************************
    *    using loaded crypto provider to generate private key     *
    **************************************************************/
    auto res_genPrKey = myProvider_crypto->GeneratePrivateKey(ECDSA_SHA_256_ALG_ID,kAllowSignature);
    if(!res_genPrKey.HasValue())
    {
        std::cout << "failed to generate private key\n";
        return 0;
    }
    auto myPrivateKey = std::move(res_genPrKey).Value();

    //Save Private Key
    //myProvider_key_storage->saveKey(*myPrivateKey, "/home/mohamed/Crypto/KeySlots/ecdsa_private.key");
   
    

    ara::core::InstanceSpecifier PRK("ecdsa_private_key_1");
    std::cout<<"BEGAIN" << std::endl;
    keys::KeySlot::Uptr private_key_slot = myProvider_key_storage->LoadKeySlot(PRK).Value();
    private_key_slot->printData();
    std::cout<<"END" << std::endl;
    //Open Key Slot
    CryptoPP_IOInterface::Uptr io_ecdsa_private = private_key_slot->Open(false, true).Value();

    std::cout << std::endl;
    myPrivateKey->Save(*io_ecdsa_private);
   
    //public Key
    auto myPublicKey = myPrivateKey->GetPublicKey().Value();
    ara::core::InstanceSpecifier PU("ecdsa_public_key_1");
    std::cout<<"BEGAIN" << std::endl;
    keys::KeySlot::Uptr public_key_slot = myProvider_key_storage->LoadKeySlot(PU).Value();
    public_key_slot->printData();
    std::cout<<"END" << std::endl;

    CryptoPP_IOInterface::Uptr publickey_io = public_key_slot->Open(false, true).Value();
    myPublicKey->Save(*publickey_io);

    TransactionScope scope;
    scope.push_back(std::move(symmetric_key_Slot));
    scope.push_back(std::move(private_key_slot));
    scope.push_back(std::move(public_key_slot));

    TransactionId transactionId = myProvider_key_storage->BeginTransaction(scope).Value();

    
  

    myProvider_key_storage->CommitTransaction(transactionId);
    
    auto loadSymmetric = myProvider_crypto->LoadSymmetricKey(*io_symmetric);
    auto loadPrivate = myProvider_crypto->LoadPrivateKey(*io_ecdsa_private);
    auto loadPublic = myProvider_crypto->LoadPublicKey(*publickey_io);


    // keys::KeySlot ks2;
    // auto res_genPrRSAKey = myProvider_crypto->GeneratePrivateKey(RSA_2048_ALG_ID,kAllowDataEncryption);
    // if(!res_genPrRSAKey.HasValue())
    // {
    //     std::cout << "failed to generate private key\n";
    //     return 0;
    // }
    // auto myPrivateRSAKey = std::move(res_genPrRSAKey).Value();
    // ks2.saveKey(*myPrivateRSAKey, "/home/mohamed/Crypto_FC-master/KeySlots/rsa_private.key");

    // ks2.saveKey(* (myPrivateRSAKey->GetPublicKey().Value()), "/home/mohamed/Crypto_FC-master/KeySlots/rsa_public.key");
    // ara::core::InstanceSpecifier PUK("rsa_4096_private_key_1");
    // std::cout<<"BEGAIN" << std::endl;
    // ks2=myProvider->LoadKeySlot(PUK).Value();
    // ks2.printData();
    // std::cout<<"END" << std::endl;
    

    

    // CryptoPP_IOInterface::Uptr privateKey_io = ks2.Open(false, true).Value();
    // std::cout << privateKey_io->GetKeyMaterialPath() << std::endl; 
    // auto load = myProvider_crypto->LoadPrivateKey(*privateKey_io);
   
    // std::cout << std::endl;

    // ara::core::InstanceSpecifier PU("rsa_4096_public_key_1");
    // std::cout<<"BEGAIN" << std::endl;
    // ks2 = myProvider->LoadKeySlot(PU).Value();
    // ks2.printData();
    // std::cout<<"END" << std::endl;

    //  CryptoPP_IOInterface::Uptr publickey_io = ks2.Open(false, true).Value();
    // std::cout << publickey_io->GetKeyMaterialPath() << std::endl; 
    // auto loadPublic = myProvider_crypto->LoadPublicKey(*publickey_io);
    // std::cout << std::endl;
    /*
    ara::core::InstanceSpecifier PRK("rsa_4096_private_key_1");
    std::cout<<"BEGAIN" << std::endl;
    myProvider->LoadKeySlot(PRK).Value();
    //ks.GetContentProps();
    std::cout<<"END" << std::endl;*/

    return 0;
}
