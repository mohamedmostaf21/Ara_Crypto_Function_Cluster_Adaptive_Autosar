#ifndef CRYPTOPP_ECDSA_PUBLIC_KEY_H
#define CRYPTOPP_ECDSA_PUBLIC_KEY_H

#include "../../../private/cryp/cryobj/public_key.h"
#include <cryptopp/rsa.h>
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
            class CryptoPP_ECDSA_PublicKey : public PublicKey
            {
            private:
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_ECDSA_PublicKey() {}

                // Copy constructor
                CryptoPP_ECDSA_PublicKey(const CryptoPP_ECDSA_PublicKey& other) {
                    mValue = other.mValue;
                }


                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PublicKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_ECDSA_PublicKey> ptr = std::make_unique<CryptoPP_ECDSA_PublicKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>("ecdsa_public.key");
                    
                    return std::move(ptr);  
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey getKey()
                {
                    return mValue;
                }


                
   
                /*            
                virtual bool CheckKey(bool strongCheck=true) const noexcept override
                {

                }

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > HashPublicKey (HashFunctionCtx &hashFunc) const noexcept override
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