#ifndef SECRET_SEED_H_
#define SECRET_SEED_H_
#include "restricted_use_object.h"
#include "../../common/mem_region.h"
namespace ara{
    namespace crypto{
        namespace cryp{
            class SecretSeed : public RestrictedUseObject
            {
            public:
                using Uptrc = std::unique_ptr<const SecretSeed>;
                using Uptr = std::unique_ptr<SecretSeed>;
                
                static const CryptoObjectType kObjectType = CryptoObjectType::kSecretSeed;


                //virtual ara::core::Result<SecretSeed::Uptr> Clone (ReadOnlyMemRegionxorDelta=ReadOnlyMemRegion()) const noexcept=0;

                virtual ara::core::Result<void> JumpFrom (const SecretSeed &from, std::int64_t steps) noexcept=0;

                virtual SecretSeed& Jump (std::int64_t steps) noexcept=0;
                
                virtual SecretSeed& Next () noexcept=0;
                
                virtual SecretSeed& operator^= (const SecretSeed &source) noexcept=0;

                virtual SecretSeed& operator^= (ReadOnlyMemRegion source) noexcept=0;
            };

        }
    }
}

#endif /* SECRET_SEED_H_ */
