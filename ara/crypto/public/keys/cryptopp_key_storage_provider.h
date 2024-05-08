#ifndef CRYPTOPP_KEY_STORAGE_PROVIDER_H_
#define CRYPTOPP_KEY_STORAGE_PROVIDER_H_
#include "../../private/keys/key_storage_provider.h"
#include "cryptopp_key_slot.h"
#include "../../public/cryp/cryobj/cryptopp_aes_128_symmetric_key.h"
#include "../../public/cryp/cryobj/cryptopp_ecdsa_sha_256_private_key.h"
#include "../../public/cryp/cryobj/cryptopp_ecdsa_sha_256_public_key.h"
#include "../../public/cryp/cryobj/cryptopp_rsa_2046_private_key.h"
#include "../../public/cryp/cryobj/cryptopp_rsa_2046_public_key.h"
#include "../../public/cryp/cryptopp_crypto_provider.h"
namespace pt = boost::property_tree;
namespace ara
{
    namespace crypto
    {
        namespace keys
        {

        
            class Cryptopp_KeyStorageProvider : public KeyStorageProvider
            {
                private:
                    std::vector<IOInterface::Uptr> target;
                    TransactionId serialNumber;
                public:
                Cryptopp_KeyStorageProvider() : KeyStorageProvider()
                {
                   serialNumber = 0;
                }
                ara::core::Result<KeySlot::Uptr> LoadKeySlot (ara::core::InstanceSpecifier &iSpecify) noexcept override{
                     std::string iSpecifyStr = iSpecify.ToString();
                    
                    //****************************************
                    //get access from IAM
                    //*******************************************
                    // Create a property tree object
                    pt::ptree tree;
            
                    try {
                        // Parse the JSON file into the property tree
                        pt::read_json("/home/mohamed/Crypto/ara/crypto/public/Manifest/CryptoKeySlotManifest.json", tree);
                        
                        //object of keyslot class
                        KeySlot::Uptr my_key_slot = std::make_unique<Cryptopp_KeySlot>();
        
                        // Access data 
                        for (const auto& keySlot : tree.get_child("KeySlots")) {
                            std::string instanceSpecifier = keySlot.second.get<std::string>("InstanceSpecifier", "");
                            
                           
                            if (instanceSpecifier == iSpecifyStr) {
                                std::string slotType = keySlot.second.get<std::string>("SlotType", "");
                            
                                std::string object = keySlot.second.get<std::string>("CryptoObjectType", "");
                                std::string AllowedFlage = keySlot.second.get<std::string>("AllowedUsageFlags", "");
                                my_key_slot->setmeta(instanceSpecifier,keySlot.second.get<std::string>("CryptoProvider", ""),keySlot.second.get<std::string>("KeyMaterialPath", ""),keySlot.second.get<CryptoAlgId>("AlgId", kAlgIdDefault), static_cast<AllowedUsageFlags>(strtol(AllowedFlage.data(), nullptr, 16)), my_key_slot->GetObjectType(object),keySlot.second.get<bool>("Exportable", true),  my_key_slot->GetSlotType(slotType)  ,keySlot.second.get<std::size_t>("SlotCapacity"),keySlot.second.get<bool>("AllocateShadowCopy", true),keySlot.second.get<bool>("AllowContentTypeChange", true),keySlot.second.get<int32_t>("MaxUpdateAllowed"));
                            }
                        }
                       
                        return  ara::core::Result<KeySlot::Uptr>::FromValue(std::move(my_key_slot)); 
                    } catch (const std::exception& e) {
                        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
                         return  ara::core::Result<KeySlot::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kLogicFault, NoSupplementaryDataForErrorDescription)); 
                    }
                  
                  
                }






                ara::core::Result<TransactionId> BeginTransaction (const TransactionScope &targetSlots) noexcept override
                {
                    std::cout << "begin function\n";
                    for (const auto& slot : targetSlots) 
                    {                     
                        target.push_back(std::move(slot->Open().Value()));
                        std::cout << "loop in begin\n";                 
                    }
                  
                    serialNumber++;
                    return ara::core::Result<TransactionId>::FromValue(serialNumber);       
                }

                ara::core::Result<void> CommitTransaction (TransactionId id) noexcept override
                {
                    std::cout << "Commit Transaction\n";
                    // for(auto& interface : target)
                    // {
                    //     // Release ownership of the Base pointer
                    //     //IOInterface* rawPtr = interface.release();
                    //     // Reassign the raw pointer to a new unique_ptr of the Derived class
                    //     auto derivedPtr = dynamic_cast<const CryptoPP_IOInterface&>(*interface);
                    //    std::cout << derivedPtr.GetPrimitiveId() << std::endl;
                    //     if(derivedPtr.GetCryptoObjectType() == CryptoObjectType::kSymmetricKey && derivedPtr.GetPrimitiveId() == AES_ECB_128_ALG_ID){
                           
                    //        CryptoPP::FileSink file(derivedPtr.GetKeyMaterialPath().c_str());
                    //         for (size_t i = 0; i < derivedPtr.getSymmetricKey().size(); i++) {
                    //             printf("%02x",  derivedPtr.getSymmetricKey()[i]);
                    //         }
                    //         std::cout << std::endl;
                    //         file.Put(derivedPtr.getSymmetricKey(), derivedPtr.getSymmetricKey().size());
                    //     }else if(derivedPtr.GetCryptoObjectType() == CryptoObjectType::kPrivateKey && derivedPtr.GetPrimitiveId() == ECDSA_SHA_256_ALG_ID){
                    //         // declares an object of ByteQueue (a queue of bytes used to store binary data)
                    //         CryptoPP::ByteQueue queue;
                    //         derivedPtr.getPrivateEcdsaKey().Save(queue);
                    //         CryptoPP::FileSink file(derivedPtr.GetKeyMaterialPath().c_str());
    
                    //         // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                    //         // effectively writing the key data to the file.
                    //         queue.CopyTo(file);

                    //         // signals the end of the message to the FileSink
                    //         file.MessageEnd();     
                            
                    //     }
                    //     else if(derivedPtr.GetCryptoObjectType() == CryptoObjectType::kPublicKey && derivedPtr.GetPrimitiveId() == ECDSA_SHA_256_ALG_ID){
                    //         // declares an object of ByteQueue (a queue of bytes used to store binary data)
                    //         CryptoPP::ByteQueue queue;
                    //         derivedPtr.getPublicEcdsaKey().Save(queue);
                    //         CryptoPP::FileSink file(derivedPtr.GetKeyMaterialPath().c_str());

                    //         // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                    //         // effectively writing the key data to the file.
                    //         queue.CopyTo(file);

                    //         // signals the end of the message to the FileSink
                    //         file.MessageEnd();  
                    //     }else if(derivedPtr.GetCryptoObjectType() == CryptoObjectType::kPrivateKey && derivedPtr.GetPrimitiveId() == RSA_2048_ALG_ID){
                    //         // declares an object of ByteQueue (a queue of bytes used to store binary data)
                    //         CryptoPP::ByteQueue queue;
                    //         derivedPtr.getPrivateRsaKey().Save(queue);
                    //         CryptoPP::FileSink file(derivedPtr.GetKeyMaterialPath().c_str());
    
                    //         // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                    //         // effectively writing the key data to the file.
                    //         queue.CopyTo(file);

                    //         // signals the end of the message to the FileSink
                    //         file.MessageEnd();     
                    //     }else if(derivedPtr.GetCryptoObjectType() == CryptoObjectType::kPublicKey && derivedPtr.GetPrimitiveId() == RSA_2048_ALG_ID){
                    //         // declares an object of ByteQueue (a queue of bytes used to store binary data)
                    //         CryptoPP::ByteQueue queue;
                    //         derivedPtr.getPublicRsaKey().Save(queue);
                    //         CryptoPP::FileSink file(derivedPtr.GetKeyMaterialPath().c_str());
                    //         // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                    //         // effectively writing the key data to the file.
                    //         queue.CopyTo(file);

                    //         // signals the end of the message to the FileSink
                    //         file.MessageEnd();  
                    //     }
                       
                    //     std::cout << "loop in commit\n";                 
                    // }
                    return ara::core::Result<void>::FromValue();
                }

                void  saveKey(const SymmetricKey& key, const std::string& filename) override
                {
                    std::cout << "Saving Begain" << std::endl;
                   try{
                        auto aesKey = dynamic_cast<const CryptoPP_AES_128_SymmetricKey&>(key);
                        auto value = aesKey.getValue();
                        std::cout << "Random AES key: ";
                            for (size_t i = 0; i < value.size(); i++) {
                                printf("%02x", value[i]);
                            }
                            std::cout << std::endl;
                        
                            CryptoPP::FileSink output(filename.c_str());
                            output.Put(value, value.size());

                   }catch (const std::bad_cast& e) // return error
                    {
                        // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                        std::cout << " Error bad Casting " << std::endl;
                    }

                }

                void saveKey(const PrivateKey& key, const std::string& filename) override
                {

                    std::cout << "Saving Begain" << std::endl;
                
                   try{
                        
                        auto ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_PrivateKey&>(key);
                        auto value = ecdsaKey.getValue();
                        std::cout << "Random ECDSA private key : Getting";
                        
                        CryptoPP::ByteQueue queue;
                        value.Save(queue);
                        CryptoPP::FileSink file(filename.c_str());
                        
                        queue.CopyTo(file);
                        file.MessageEnd();
                        std::cout << std::endl;
                    }catch (const std::bad_cast& e) // return error
                    {
                        // Failed to cast  PrivateKey to CryptoPP_ECDSA_PrivateKey
                        try{
                            auto rsaKey = dynamic_cast<const CryptoPP_RSA_2046_PrivateKey&>(key);
                            auto value = rsaKey.getValue();
                            std::cout << "Random Rsa private key : Getting";
                            CryptoPP::ByteQueue queue;
                            value.Save(queue);
                            CryptoPP::FileSink file(filename.c_str());
                            
                            queue.CopyTo(file);
                            file.MessageEnd();
                            std::cout << std::endl;
                        }catch(const std::bad_cast& e){
                            std::cout << "Error bad Casting for second casting" << std::endl;
                        }
                     
                       
                    }

                }

                void saveKey(const PublicKey& key, const std::string& filename) override
                {
                    std::cout << "Saving Begain" << std::endl;
                   try{
                        
                        auto ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_SHA_256_PublicKey&>(key);
                        auto value = ecdsaKey.getValue();
                        std::cout << "Random ECDSA public key : Getting";
                        CryptoPP::ByteQueue queue;
                        value.Save(queue);
                        CryptoPP::FileSink file(filename.c_str());
                        
                        queue.CopyTo(file);
                        file.MessageEnd();
                        std::cout << std::endl;
                   }catch (const std::bad_cast& e) // return error
                    {
                        // Failed to cast  PrivateKey to CryptoPP_ECDSA_PrivateKey
                        try{
                            auto rsaKey = dynamic_cast<const CryptoPP_RSA_2046_PublicKey&>(key);
                            auto value = rsaKey.getValue();
                            std::cout << "Random Rsa public key : Getting";
                            CryptoPP::ByteQueue queue;
                            value.Save(queue);
                            CryptoPP::FileSink file(filename.c_str());
                            
                            queue.CopyTo(file);
                            file.MessageEnd();
                            std::cout << std::endl;
                        }catch(const std::bad_cast& e){
                             std::cout << "Error bad Casting for second casting" << std::endl;
                        }
                    
                    }

                }
            };

        }
    }
}
#endif /* CRYPTOPP_KEY_STORAGE_PROVIDER_H_ */
