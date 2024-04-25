#ifndef PRIVATE_KEY_H
#define PRIVATE_KEY_H

#include "restricted_use_object.h"
#include "public_key.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class PrivateKey : public RestrictedUseObject
            {
            public:
                using Uptrc = std::unique_ptr<const PrivateKey>;
                
                static const CryptoObjectType kObjectType = CryptoObjectType::kPrivateKey;
                
                virtual ara::core::Result<PublicKey::Uptrc> GetPublicKey () const noexcept=0;
            };
        }
    }
}


#endif
