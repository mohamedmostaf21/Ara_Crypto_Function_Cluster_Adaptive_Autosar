#ifndef CRYPTOPP_HMAC_SHA256_SIGNATURE_H
#define CRYPTOPP_HMAC_SHA256_SIGNATURE_H

#include "../../../private/cryp/cryobj/signature.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_HMAC_SHA256_Signature : public Signature
            {
            private:
                /******** attributes **********/
                const CryptoPrimitiveId::AlgId mAlgId{1};
                const std::size_t mHashSize{256};
                CryptoPP::SecByteBlock mValue;

            public:
                /************ constructor **************/
                CryptoPP_HMAC_SHA256_Signature() {}
                

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

                void setValue(CryptoPP::SecByteBlock val){
                    mValue = val;
                }

                CryptoPP::SecByteBlock GetDigestValue() const{
                    return this->mValue;
                }

            };
        }
    }
}
#endif