#ifndef MSG_RECOVERY_PUBLIC_CTX_H     
#define MSG_RECOVERY_PUBLIC_CTX_H

#include "../../../core/utility.h"
#include "../common/mem_region.h"
#include "crypto_context.h"
#include "cryobj/public_key.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class MsgRecoveryPublicCtx : public CryptoContext
            {
            public:
                using Uptr = std::unique_ptr<MsgRecoveryPublicCtx>;
                
                //virtual ExtensionService::Uptr GetExtensionService () const noexcept=0;

                virtual std::size_t GetMaxInputSize (bool suppressPadding=false) const noexcept=0;
                
                virtual std::size_t GetMaxOutputSize (bool suppressPadding=false) const noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > DecodeAndVerify (ReadOnlyMemRegion in) const noexcept=0;

                //virtual ara::core::Result<void> Reset () noexcept=0;

                virtual ara::core::Result<void> SetKey (const PublicKey &key) noexcept=0;
            };
        }
    }
}

#endif