#ifndef CRYPTOPP_HMAC_SHA512_SIGNATURE_H
#define CRYPTOPP_HMAC_SHA512_SIGNATURE_H

#include "../../../private/cryp/cryobj/signature.h"
#include <cryptopp/secblock.h>
#include "../../common/cryptopp_io_interface.h"
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_HMAC_SHA512_Signature : public Signature
            {
            private:
                /******** attributes **********/
                const CryptoPrimitiveId::AlgId mAlgId{2};
                const std::size_t mHashSize{512};
                CryptoPP::SecByteBlock mValue;

            public:
                /************ constructor **************/
                CryptoPP_HMAC_SHA512_Signature() {}
                

                std::size_t GetPayloadSize () const noexcept override
                {
                    return 32;
                }

                /************* override pure virtual functions related to Signature *************/
                CryptoPrimitiveId::AlgId GetHashAlgId () const noexcept override
                {
                    return mAlgId;
                }
                
                // Get the hash size required by current signature algorithm in byte
                std::size_t GetRequiredHashSize () const noexcept override
                {
                    return mHashSize;
                }
                
                /************ getter and setter ***********/
                std::vector<std::uint8_t> getValue() const{
                    return std::vector<std::uint8_t>(mValue.begin(), mValue.end());
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
                void setValue(CryptoPP::SecByteBlock val) noexcept override{
                    mValue = val;
                }

                CryptoPP::SecByteBlock GetDigestValue() const noexcept  override{
                    return this->mValue;
                }

            };
        }
    }
}
#endif