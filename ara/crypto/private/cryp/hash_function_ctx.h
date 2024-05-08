#ifndef HASH_FUNCTION_CTX_H
#define HASH_FUNCTION_CTX_H

#include "../../../core/result.h"
#include "../../../core/utility.h"
#include "../common/mem_region.h"
#include "crypto_context.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class HashFunctionCtx : public CryptoContext
            {
            
            public:
                using Uptr = std::unique_ptr<HashFunctionCtx>;
                

                /**************** pure virtual fuctions *****************/
                //virtual DigestService::Uptr GetDigestService () const noexcept=0;
                 
                virtual ara::core::Result<void> Start () noexcept=0;
                      
                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv) noexcept=0;

                //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept=0;

                virtual ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept=0;

                //virtual ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept=0;

                virtual ara::core::Result<void> Update (std::uint8_t in) noexcept=0;
                      
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > Finish () noexcept=0;
                            
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest (std::size_t offset=0) noexcept=0;
            };
        }
    }
}

#endif