#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "crypto_object.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class Signature : public CryptoObject
            {
            public:
                using Uptrc = std::unique_ptr<const Signature>;
                
                static const CryptoObjectType kObjectType = CryptoObjectType::kSignature;

                virtual CryptoPrimitiveId::AlgId GetHashAlgId () const noexcept=0;
                
                virtual std::size_t GetRequiredHashSize () const noexcept=0;
            };
        }
    }

}

#endif