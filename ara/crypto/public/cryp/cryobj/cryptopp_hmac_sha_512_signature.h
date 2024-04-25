#ifndef CRYPTOPP_HMAC_SHA512_SIGNATURE_H
#define CRYPTOPP_HMAC_SHA512_SIGNATURE_H

#include "../../../private/cryp/cryobj/signature.h"
#include "../cryptopp_sha_512_hash_function_ctx.h"

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
                
                /************* override pure virtual functions related to Signature *************/
                virtual CryptoPrimitiveId::AlgId GetHashAlgId () const noexcept override
                {
                    return mAlgId;
                }
                
                /*
                Get the hash size required by current signature algorithm in byte
                */
                virtual std::size_t GetRequiredHashSize () const noexcept override
                {
                    return mHashSize;
                }
                

                // not autosar
                void setValue(CryptoPP::SecByteBlock val){
                    mValue = val;
                }

                std::vector<std::uint8_t> getValue() const{
                    return std::vector<std::uint8_t>(mValue.begin(), mValue.end());
                }

                CryptoPP::SecByteBlock GetDigestValue() const{
                    return this->mValue;
                }
            };
        }
    }
}
#endif