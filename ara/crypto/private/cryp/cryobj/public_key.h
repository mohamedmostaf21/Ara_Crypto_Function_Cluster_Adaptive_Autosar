#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include "restricted_use_object.h"
#include "../../../../core/utility.h"
#include "../hash_function_ctx.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class PublicKey : public RestrictedUseObject
            {
            public:
                using Uptrc = std::unique_ptr<const PublicKey>;

                static const CryptoObjectType kObjectType = CryptoObjectType::kPublicKey;
                
                /*
                virtual bool CheckKey(bool strongCheck=true) const noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > HashPublicKey (HashFunctionCtx &hashFunc) const noexcept=0;
                */
            };
        }
    }
}


#endif
