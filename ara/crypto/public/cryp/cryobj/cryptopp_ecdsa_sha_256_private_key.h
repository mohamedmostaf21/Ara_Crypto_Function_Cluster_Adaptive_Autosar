#ifndef CRYPTOPP_ECDSA__SHA_256_PRIVATE_KEY_H
#define CRYPTOPP_ECDSA__SHA_256_PRIVATE_KEY_H

#include "../../../private/cryp/cryobj/private_key.h"
#include "cryptopp_ecdsa_sha_256_public_key.h"
#include "loadKey.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include "../../../public/common/cryptopp_io_interface.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_ECDSA_PrivateKey : public PrivateKey
            {
            private:
                /************ attributes ***************/
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_ECDSA_PrivateKey() {}

                /************ Copy constructor *********/
                CryptoPP_ECDSA_PrivateKey(const CryptoPP_ECDSA_PrivateKey& other) {
                    mValue = other.mValue;
                }

                /************ getter and setter ***********/
                void setValue(CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey mValue)
                {
                    this->mValue = mValue;
                }

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey getValue()
                {
                    return mValue;
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

            
                /************* override parent functions ************/

                virtual ara::core::Result<PublicKey::Uptrc> GetPublicKey () const noexcept override
                {
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;

                    mValue.MakePublicKey(publicKey);

                    std::unique_ptr<CryptoPP_ECDSA_SHA_256_PublicKey> ptr = std::make_unique<CryptoPP_ECDSA_SHA_256_PublicKey>();
                  
                    ptr->setValue(publicKey);

                    return ara::core::Result<PublicKey::Uptrc>(std::move(ptr));
                }

                Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowSignature;
                }

                std::size_t GetPayloadSize () const noexcept override
                {
                    return 32;
                }
                ara::core::Result<void> Save (ara::crypto::IOInterface &container) const noexcept override
                {
                    
                    if(!container.IsValid()) // return error
                        return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    try 
                    {
                        CryptoPP_IOInterface& crytpopp_IoInterface = dynamic_cast<CryptoPP_IOInterface&>(const_cast<IOInterface&>(container));

                        // declares an object of ByteQueue (a queue of bytes used to store binary data)
                        CryptoPP::ByteQueue queue; 

                        // serializes the key and stores it in the ByteQueue
                        mValue.Save(queue);

                        CryptoPP::FileSink file(crytpopp_IoInterface.GetKeyMaterialPath().c_str());
                        // copies the contents of the ByteQueue (which now contains the serialized key) to the FileSink
                        // effectively writing the key data to the file.
                        queue.CopyTo(file);

                        // signals the end of the message to the FileSink
                        file.MessageEnd();
                        
                        return ara::core::Result<void>::FromValue();
                    } 
                    catch (const std::bad_cast& e)
                    {
                        return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }   


                bool IsSession () const noexcept override
                {
                    //temporary
                    return true;
                }
                /*
                virtual COIdentifier GetObjectId () const noexcept override

                virtual COIdentifier HasDependence () const noexcept override
           
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override
                            
                virtual std::size_t GetPayloadSize () const noexcept override
                
                virtual bool IsExportable () const noexcept override
            
                virtual bool IsSession () const noexcept override
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept override
                
                */
            };
        }
    }
}





#endif