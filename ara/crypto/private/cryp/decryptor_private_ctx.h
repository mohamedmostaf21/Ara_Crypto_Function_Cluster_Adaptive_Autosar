#ifndef DECRYPTOR_PUBLIC_CTX_H
#define DECRYPTOR_PUBLIC_CTX_H

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
            class DecryptorPrivateCtx : public CryptoContext 
            {
            public:
                using Uptr = std::unique_ptr<DecryptorPrivateCtx>;
                
                //virtual CryptoService::Uptr GetCryptoService () const noexcept=0;

                virtual ara::core::Result<void> SetKey (const PrivateKey &key) noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlock ( ReadOnlyMemRegion in, 
                                                                                            bool suppressPadding=false
                                                                                            ) const noexcept=0;

                
                // virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}

#endif