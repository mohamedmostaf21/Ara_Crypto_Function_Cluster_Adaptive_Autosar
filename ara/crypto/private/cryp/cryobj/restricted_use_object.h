#ifndef RESTRICTED_USE_OBJECT_H
#define RESTRICTED_USE_OBJECT_H

#include "crypto_object.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class RestrictedUseObject : public CryptoObject
            {
            public:
                using Uptrc = std::unique_ptr<const RestrictedUseObject>;
                using Usage = AllowedUsageFlags;
                
                virtual Usage GetAllowedUsage () const noexcept=0;
            };
        }
    }
}

#endif