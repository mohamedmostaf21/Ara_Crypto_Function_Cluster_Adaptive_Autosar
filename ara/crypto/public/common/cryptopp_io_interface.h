#ifndef CRYPTOPP_IO_INTERFACE_H_
#define CRYPTOPP_IO_INTERFACE_H_
#include "../../private/common/io_interface.h"
#include "../../public/cryp/cryobj/cryptopp_crypto_primitive_id.h"
#include "../../private/keys/key_slot_prototype_props.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include <cryptopp/files.h>
#include <cryptopp/rsa.h>

#include <filesystem>
namespace ara
{
    namespace crypto 
    {
        
       
        class CryptoPP_IOInterface : public IOInterface
        {
            private:
            
            keys::KeySlotPrototypeProps mKeySlotPrototypeProps;
            CryptoPP::ByteQueue queue;     
            CryptoPP::SecByteBlock  Symmetric;
        
            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey PrivateEcdsa;
            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey PublicEcdsa;
            CryptoPP::RSA::PrivateKey PrivateRsa;
            CryptoPP::RSA::PublicKey PublicRsa;
      

            CryptoAlgId mAlgId;
            
            AllowedUsageFlags mContentAllowedUsage;
            std::string KeyMaterialPath;
            bool mExportAllowed;
            
            std::size_t mSlotCapacity;
            
            CryptoObjectType mObjectType;
            public:
            CryptoPP_IOInterface() : IOInterface()
            {
             
            }
            CryptoPP_IOInterface( std::string path,
                              keys::KeySlotPrototypeProps k
                            ) : IOInterface()
            {
                this->KeyMaterialPath = path;
                this->mKeySlotPrototypeProps = k;
               
            }

            CryptoPP_IOInterface(const CryptoPP_IOInterface& obj)
            { 
                KeyMaterialPath = obj.KeyMaterialPath;
                mKeySlotPrototypeProps =  obj.mKeySlotPrototypeProps;
            }
            void setSymmetric(CryptoPP::SecByteBlock mValue)
            {
                this->Symmetric = mValue;
            }    
            void setPrivateEcdsa(CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey mValue)
            {
                this->PrivateEcdsa = mValue;
            }   
            void setPublicEcdsa( CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey mValue)
            {
                this->PublicEcdsa = mValue;
            }           

            void setPrivateRsa(CryptoPP::RSA::PrivateKey mValue)
            {
                this->PrivateRsa = mValue;
            }
            
            void setPublicRsa( CryptoPP::RSA::PublicKey mValue)
            {
                this->PublicRsa = mValue;
            }
        
            // Getter for AES 128 Symmetric Key
             CryptoPP::SecByteBlock getSymmetricKey()  {
                return Symmetric;
            }

            // Getter for ECDSA Private Key
            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey getPrivateEcdsaKey()  {
                return PrivateEcdsa;
            }

            // Getter for ECDSA SHA-256 Public Key
          CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey  getPublicEcdsaKey()  {
                return PublicEcdsa;
            }

            // Getter for RSA 2046 Private Key
            CryptoPP::RSA::PrivateKey getPrivateRsaKey()  {
                return PrivateRsa;
            }

            // Getter for RSA 2046 Public Key
            CryptoPP::RSA::PublicKey getPublicRsaKey()  {
                return PublicRsa;
            }


            void setInterface(keys::KeySlotPrototypeProps mKeySlotPrototypeProps, std::string KeyMaterialPath) 
            {
                this->mKeySlotPrototypeProps = mKeySlotPrototypeProps;
                this->KeyMaterialPath = KeyMaterialPath;
            }
            /************* override parent functions ************/
           
            AllowedUsageFlags GetAllowedUsage () const noexcept override
            {
                return  this->mKeySlotPrototypeProps.mContentAllowedUsage;
            }

            std::size_t GetCapacity () const noexcept override
            {
                return  this->mKeySlotPrototypeProps.mSlotCapacity;
            }
            std::size_t GetPayloadSize () const noexcept override
            {
                return 16;
            }

            CryptoObjectType GetCryptoObjectType () const noexcept override
            {
                return  this->mKeySlotPrototypeProps.mObjectType;
            }

            bool IsObjectExportable () const noexcept override
            {
                return this->mKeySlotPrototypeProps.mExportAllowed;
            }
        
            // CryptoObjectUid GetObjectId () const noexcept override
            // {   
            //     return  ks.GetPrototypedProps().Value().;
            // }
           
        
            CryptoAlgId GetPrimitiveId () const noexcept override
            {
                return    this->mKeySlotPrototypeProps.mAlgId ;
            }
        
            std::string GetKeyMaterialPath() const noexcept 
            {
                return    this->KeyMaterialPath;
            }

             bool IsValid () const noexcept override
            {
                std::string invalidChars = "\\:*?\"<>|";
    
                // Check for invalid characters and spaces
                for (char c : KeyMaterialPath) {
                    if (invalidChars.find(c) != std::string::npos || c == ' ') {
                        return false;
                    }
                }
                
                // Check for file extension ".key"
                if (KeyMaterialPath.length() < 4 || KeyMaterialPath.substr(KeyMaterialPath.length() - 4) != ".key") {
                    return false;
                }
                
                return true;
            }

            bool IsWritable () const noexcept override
            {
                if(!IsValid())
                    return false;

                std::filesystem::file_status status = std::filesystem::status(KeyMaterialPath);
                std::filesystem::perms permissions = status.permissions();

                return (permissions & std::filesystem::perms::owner_write) != std::filesystem::perms::none;
            }

            void SetQueue(CryptoPP::ByteQueue queue)
            {
                this->queue = queue;
            }

            CryptoPP::ByteQueue GetQueue()
            {
                return queue;
            }

        
            // CryptoObjectType GetTypeRestriction () const noexcept override
            // {

            // }
            


        };
    }
}
#endif /* CRYPTOPP_IO_INTERFACE_H_ */
