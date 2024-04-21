#ifndef CRYPTOPP_ECDSA_PRIVATE_KEY_H
#define CRYPTOPP_ECDSA_PRIVATE_KEY_H

#include "../../../private/cryp/cryobj/private_key.h"
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include "cryptopp/hex.h"
#include <iostream>
#include <string>
#include "loadKey.h"


#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_ECDSA_PrivateKey : public PrivateKey
            {
            private:
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_ECDSA_PrivateKey() {}

                // Copy constructor
                CryptoPP_ECDSA_PrivateKey(const CryptoPP_ECDSA_PrivateKey& other) {
                    mValue = other.mValue;
                }


                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PrivateKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_ECDSA_PrivateKey> ptr = std::make_unique<CryptoPP_ECDSA_PrivateKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>("ecdsa_private.key");
                    
                    return std::move(ptr);  
                }

                /*************************************************************
                * not autosar but until key storage provider is implemented
                **************************************************************/
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey getKey()
                {
                    return mValue;
                }


                
   
                /*
                virtual ara::core::Result<PublicKey::Uptrc> GetPublicKey () const noexcept override
                {

                }

                */


                /************* override parent functions ************/
                virtual Usage GetAllowedUsage () const noexcept override
                {
                    return 5;
                }

                /*
                virtual COIdentifier GetObjectId () const noexcept override
                {
                    
                }

                virtual COIdentifier HasDependence () const noexcept override
                {
                    
                }
           
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override
                {
                    
                }
                
                virtual std::size_t GetPayloadSize () const noexcept override
                {
                    
                }
                
                virtual bool IsExportable () const noexcept override
                {
                    
                }
                
                virtual bool IsSession () const noexcept override
                {
                    
                }
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept override
                {
                    
                }
                */
            };
        }
    }
}





#endif