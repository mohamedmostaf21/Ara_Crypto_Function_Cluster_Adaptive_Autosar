#ifndef SIG_ENCODE_PRIVATE_CTX_H     
#define SIG_ENCODE_PRIVATE_CTX_H

#include "../../../core/utility.h"
#include "../common/mem_region.h"
#include "crypto_context.h"
#include "cryobj/private_key.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class SigEncodePrivateCtx : public CryptoContext
            {
            public:
                using Uptr = std::unique_ptr<SigEncodePrivateCtx>;
                
                virtual std::size_t GetMaxInputSize (bool suppressPadding=false) const noexcept=0;

                virtual std::size_t GetMaxOutputSize (bool suppressPadding=false) const noexcept=0;

                virtual ara::core::Result<void> SetKey (const PrivateKey &key) noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > SignAndEncode (ReadOnlyMemRegion in) const noexcept=0;

                //virtual ExtensionService::Uptr GetExtensionService () const noexcept=0;

                //virtual ara::core::Result<void> Reset () noexcept=0;                
            };
        }
    }
}

#endif