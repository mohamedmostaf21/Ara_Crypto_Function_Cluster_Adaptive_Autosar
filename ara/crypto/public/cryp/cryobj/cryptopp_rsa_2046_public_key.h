#ifndef CRYPTOPP_RSA_PUBLIC_KEY_H
#define CRYPTOPP_RSA_PUBLIC_KEY_H

#include "../../../private/cryp/cryobj/public_key.h"
#include <cryptopp/rsa.h>
#include "loadKey.h"
#include "../../../public/common/cryptopp_io_interface.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_RSA_2046_PublicKey : public PublicKey
            {
            private:
                /************ attributes ***************/
                CryptoPP::RSA::PublicKey mValue;

            public:
                /************ constructor **************/
                CryptoPP_RSA_2046_PublicKey() {}

                /************ Copy constructor *********/
                CryptoPP_RSA_2046_PublicKey(const CryptoPP_RSA_2046_PublicKey& other) {
                    mValue = other.mValue;
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<PublicKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_RSA_2046_PublicKey> ptr = std::make_unique<CryptoPP_RSA_2046_PublicKey>();
                  
                    ptr->mValue = loadKey<CryptoPP::RSA::PublicKey>("rsa_public.key");
                    
                    return std::move(ptr);  
                }

                /************ getter and setter ***********/
                CryptoPP::RSA::PublicKey getValue()
                {
                    return mValue;
                }

                void setValue(CryptoPP::RSA::PublicKey mValue)
                {
                    this->mValue = mValue;
                }
   
                /************* override parent functions ************/
                Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowDataEncryption;
                }

                std::size_t GetPayloadSize () const noexcept override
                {
                    return 256;
                }

                ara::core::Result<ara::core::Vector<ara::core::Byte>> HashPublicKey (HashFunctionCtx &hashFunc) const noexcept override
                {
                    // Serialize the public key
                    std::string serializedPublicKey;
                    CryptoPP::StringSink ss(serializedPublicKey);
                    mValue.DEREncode(ss);

                    // Copy the serialized public key data into a vector
                    ara::core::Vector<ara::core::Byte> publicKeyData(serializedPublicKey.begin(), serializedPublicKey.end());

                    auto res_update =  hashFunc.Update(publicKeyData);
                    if(res_update.HasValue())
                    {
                        auto res_finish = hashFunc.Finish();
                        return std::move(res_finish);
                    }
                    else
                    {
                       return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompleteArgState, NoSupplementaryDataForErrorDescription));
                    }    
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
                bool CheckKey(bool strongCheck=true) const noexcept override

                COIdentifier GetObjectId () const noexcept override

                COIdentifier HasDependence () const noexcept override

                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override

                bool IsExportable () const noexcept override
      
                bool IsSession () const noexcept override
                
                ara::core::Result<void> Save (IOInterface &container) const noexcept override
                */
            };
        }
    }
}





#endif