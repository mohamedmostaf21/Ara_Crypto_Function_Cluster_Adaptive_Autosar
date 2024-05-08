#ifndef CRYPTOPP_AES_128_SUMMETRIC_KEY_H
#define CRYPTOPP_AES_128_SUMMETRIC_KEY_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "../../../private/cryp/cryobj/symmetric_key.h"
#include "../../../public/common/cryptopp_io_interface.h"

#define default_key_length_in_Byte  16 
#define min_key_length_in_Byte  16 
#define max_key_length_in_Byte  32 

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_AES_128_SymmetricKey : public SymmetricKey
            {
            private:
                /*************** attributes *************/
                CryptoPP::SecByteBlock mValue;

            public:
                /************ constructor **************/
                CryptoPP_AES_128_SymmetricKey() : mValue(default_key_length_in_Byte)
                {}

                /************ Copy constructor *********/
                CryptoPP_AES_128_SymmetricKey(const CryptoPP_AES_128_SymmetricKey& other) : mValue(other.mValue.size()) {
                    mValue.Assign(other.mValue, other.mValue.size());
                }

                CryptoPP_AES_128_SymmetricKey(const SymmetricKey& obj)
                { 
                   mValue = ((CryptoPP_AES_128_SymmetricKey)obj).mValue;
                }
                
                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<SymmetricKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_AES_128_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_128_SymmetricKey>();
                    
                    std::string key = "0123456789abcdef";
                    ptr->mValue.Assign((const CryptoPP::byte*)key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
                         
                    return std::move(ptr);                    
                }

                /************ getter and setter ***********/
                CryptoPP::SecByteBlock getValue()
                {
                    return mValue;
                }

                void setValue(CryptoPP::SecByteBlock mValue)
                {
                    this->mValue = mValue;
                }

                /************* override parent functions ************/
                Usage GetAllowedUsage () const noexcept override
                {
                    return kAllowKdfMaterialAnyUsage;
                }

                std::size_t GetPayloadSize () const noexcept override
                {
                    return 16;
                }

                ara::core::Result<void> Save (ara::crypto::IOInterface &container) const noexcept override
                {
                    
                    if(!container.IsValid()) // return error
                        return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    try 
                    {
                        CryptoPP_IOInterface& crytpopp_IoInterface = dynamic_cast<CryptoPP_IOInterface&>(const_cast<IOInterface&>(container));

                        CryptoPP::FileSink output(crytpopp_IoInterface.GetKeyMaterialPath().c_str());
                        output.Put(mValue, mValue.size());

                        
                        
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
                COIdentifier GetObjectId () const noexcept override

                COIdentifier HasDependence () const noexcept override

                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override
                              
                bool IsExportable () const noexcept override
                
                

                ara::core::Result<void> Save (IOInterface &container) const noexcept override
                */
            };
        }
    }
}


#endif