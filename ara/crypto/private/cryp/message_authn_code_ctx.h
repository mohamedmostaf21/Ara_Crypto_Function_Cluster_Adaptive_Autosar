#ifndef MESSAGE_AUTH_CODE_CTX
#define MESSAGE_AUTH_CODE_CTX

#include "../../../core/utility.h"
#include "../common/mem_region.h"
#include "crypto_context.h"
#include "cryobj/symmetric_key.h"
#include "cryobj/signature.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class MessageAuthnCodeCtx : public CryptoContext
            {
            public:
                using Uptr = std::unique_ptr<MessageAuthnCodeCtx>;
                

                /**************** pure virtual fuctions *****************/
                //virtual DigestService::Uptr GetDigestService () const noexcept=0;

                virtual ara::core::Result<void> SetKey ( const SymmetricKey &key, 
                                                        CryptoTransform transform=CryptoTransform::kMacGenerate) noexcept=0;

                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept=0;

                //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept=0;

                //virtual ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept=0;

                virtual ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept=0;

                virtual ara::core::Result<void> Update (std::uint8_t in) noexcept=0;
                
                virtual ara::core::Result<Signature::Uptrc> Finish (bool makeSignatureObject=false) noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest (std::size_t offset=0) const noexcept=0;

                virtual ara::core::Result<bool> Check (const Signature &expected) const noexcept=0;

                // virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}

#endif