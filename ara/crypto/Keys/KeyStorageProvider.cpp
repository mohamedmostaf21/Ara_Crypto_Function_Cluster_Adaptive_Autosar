#include"KeyStorageProvider.h"
#include"../../core/vector.h"
#include "../private/common/crypto_error_domain.h"


namespace ara
{
    namespace crypto
    {
        namespace keys
        {
      
                ara::core::Result<KeySlot> KeyStorageProvider::LoadKeySlot(ara::core::InstanceSpecifier &iSpecify) noexcept
                {
                    std::string iSpecifyStr = iSpecify.ToString();
                    
                    //****************************************
                    //get access from IAM
                    //*******************************************
                    // Create a property tree object
                    pt::ptree tree;
            
                    try {
                        // Parse the JSON file into the property tree
                        pt::read_json("/home/shahd/my_implmentation/Crypto_FC-master/CryptoKeySlotManifest.json", tree);
                        
                        //object of keyslot class
                        KeySlot my_key_slot;
        
                        // Access data 
                        for (const auto& keySlot : tree.get_child("KeySlots")) {
                            std::string instanceSpecifier = keySlot.second.get<std::string>("InstanceSpecifier", "");
                            
                           
                            if (instanceSpecifier == iSpecifyStr) {
                                std::string slotType = keySlot.second.get<std::string>("SlotType", "");
                            
                                std::string object = keySlot.second.get<std::string>("CryptoObjectType", "");
                                std::string AllowedFlage = keySlot.second.get<std::string>("AllowedUsageFlags", "");
                                my_key_slot.setmeta(instanceSpecifier,keySlot.second.get<std::string>("CryptoProvider", ""),keySlot.second.get<std::string>("KeyMaterialPath", ""),keySlot.second.get<CryptoAlgId>("AlgId", kAlgIdDefault), static_cast<AllowedUsageFlags>(strtol(AllowedFlage.data(), nullptr, 16)), my_key_slot.GetObjectType(object),keySlot.second.get<bool>("Exportable", true),  my_key_slot.GetSlotType(slotType)  ,keySlot.second.get<std::size_t>("SlotCapacity"),keySlot.second.get<bool>("AllocateShadowCopy", true),keySlot.second.get<bool>("AllowContentTypeChange", true),keySlot.second.get<int32_t>("MaxUpdateAllowed"));
                            }
                        }
                       
                        return  ara::core::Result<KeySlot>::FromValue(my_key_slot); 
                    } catch (const std::exception& e) {
                        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
                         return  ara::core::Result<KeySlot>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kLogicFault, NoSupplementaryDataForErrorDescription)); 
                    }
                  
                }
              
                void KeyStorageProvider::saveKey(const SymmetricKey& key, const std::string& filename)
                {
                    std::cout << "Saving Begain" << std::endl;
                   try{
                        auto aesKey = dynamic_cast<const CryptoPP_AES_128_SymmetricKey&>(key);
                        auto value = aesKey.getValue();
                        /*std::cout << "Random AES key: ";
                            for (size_t i = 0; i < value.size(); i++) {
                                printf("%02x", value[i]);
                            }
                            std::cout << std::endl;*/
                        
                            CryptoPP::FileSink output(filename.c_str());
                            output.Put(value, value.size());

                   }catch (const std::bad_cast& e) // return error
                    {
                        // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                        std::cout << " Error bad Casting " << std::endl;
                    }

                }

                void KeyStorageProvider::saveKey(const PrivateKey& key, const std::string& filename)
                {

                    std::cout << "Saving Begain" << std::endl;
                
                   try{
                        
                        auto ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_PrivateKey&>(key);
                        auto value = ecdsaKey.getValue();
                        //std::cout << "Random ECDSA private key : Getting";
                        
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
                void KeyStorageProvider::saveKey(const PublicKey& key, const std::string& filename)
                {
                    std::cout << "Saving Begain" << std::endl;
                   try{
                        
                        auto ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_SHA_256_PublicKey&>(key);
                        auto value = ecdsaKey.getValue();
                        //std::cout << "Random ECDSA public key : Getting";
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

            
        }
    }
}               




















