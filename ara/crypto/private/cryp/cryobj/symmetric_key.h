#ifndef SUMMETRIC_KEY_H
#define SUMMETRIC_KEY_H

#include "restricted_use_object.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class SymmetricKey : public RestrictedUseObject
            {
            public:
                using Uptrc = std::unique_ptr<const SymmetricKey>;
                
                static const CryptoObjectType kObjectType = CryptoObjectType::kSymmetricKey;
            };
        }
    }
}


#endif