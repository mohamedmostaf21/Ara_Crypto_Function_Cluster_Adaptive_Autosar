#ifndef CRYPTOPP_RSA_PRIVATE_KEY_H
#define CRYPTOPP_RSA_PRIVATE_KEY_H

#include "../../../private/cryp/cryobj/private_key.h"
#include "cryptopp_rsa_2046_public_key.h"
#include <cryptopp/rsa.h>
#include "loadKey.h"
#include "../../../public/common/cryptopp_io_interface.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_RSA_2046_PrivateKey : public PrivateKey
            {
            private:
                /************ attributes ***************/
                CryptoPP::RSA::PrivateKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_RSA_2046_PrivateKey() {}

                /************ Copy constructor *********/
                CryptoPP_RSA_2046_PrivateKey(const CryptoPP_RSA_2046_PrivateKey& other) {
                    mValue = other.mValue;
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PrivateKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_RSA_2046_PrivateKey> ptr = std::make_unique<CryptoPP_RSA_2046_PrivateKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::RSA::PrivateKey>("rsa_private.key");
                    
                    return std::move(ptr);  
                }

                /************ getter and setter ***********/
                CryptoPP::RSA::PrivateKey getValue()
                {
                    return mValue;
                }

                void setValue(CryptoPP::RSA::PrivateKey mValue)
                {
                    this->mValue = mValue;
                }
   
                /************* override parent functions ************/
                ara::core::Result<PublicKey::Uptrc> GetPublicKey () const noexcept override
                {
                    CryptoPP::RSA::PublicKey publicKey(mValue);

                    std::unique_ptr<CryptoPP_RSA_2046_PublicKey> ptr = std::make_unique<CryptoPP_RSA_2046_PublicKey>();
                  
                    ptr->setValue(publicKey);

                    return ara::core::Result<PublicKey::Uptrc>(std::move(ptr));
                }

                Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowDataDecryption;
                }

                std::size_t GetPayloadSize () const noexcept override
                {
                    return 256;
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

                virtual bool IsExportable () const noexcept override

                virtual bool IsSession () const noexcept override
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept override
                
                */
            };
        }
    }
}





#endif