#ifndef AUTH_CIPHER_CTX_H
#define AUTH_CIPHER_CTX_H
#include "crypto_context.h"
#include "../../../core/result.h"
#include "../../../core/optional.h"
#include "../../../core/utility.h"
#include "../../../core/vector.h"
#include "../common/mem_region.h"
#include "cryobj/restricted_use_object.h"
#include "cryobj/symmetric_key.h"
#include "digest_service.h"
#include "cryobj/signature.h"
#include "cryobj/secret_seed.h"
namespace ara{
    namespace crypto{
        namespace cryp{
            class AuthCipherCtx : public CryptoContext 
            {
            public:
                using Uptr = std::unique_ptr<AuthCipherCtx>;

                
                virtual ara::core::Result<bool> Check (const Signature &expected) const noexcept=0;

                //virtual DigestService::Uptr GetDigestService () const noexcept=0;
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte>> GetDigest(std::size_t offset=0)const noexcept=0;
                virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;

                virtual std::uint64_t GetMaxAssociatedDataSize () const noexcept=0;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessConfidentialData (ReadOnlyMemRegion in,
                                                                                                        ara::core::Optional<ReadOnlyMemRegion> expectedTag
                                                                                                    ) noexcept=0;

                // virtual ara::core::Result<void> ProcessConfidentialData(ReadWriteMemRegion inOut,
                //                                                         ara::core::Optional<ReadOnlyMemRegion> expectedTag
                //                                                     )noexcept=0;

                // ara::core::Result<void> Reset () noexcept=0;
                
                virtual ara::core::Result<void> SetKey ( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                    ) noexcept=0;

                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept=0;

                //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept=0;

                // virtual ara::core::Result<void> UpdateAssociatedData (const RestrictedUseObject &in) noexcept=0;

                virtual ara::core::Result<void> UpdateAssociatedData (ReadOnlyMemRegion in) noexcept=0;

                virtual ara::core::Result<void> UpdateAssociatedData (std::uint8_t in) noexcept=0;
            };
        }
    }
}

#endif /* AUTH_CIPHER_CTX_H */
