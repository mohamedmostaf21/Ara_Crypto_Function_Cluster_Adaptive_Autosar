#ifndef RANDOM_GENERATOR_CTX_H_
#define RANDOM_GENERATOR_CTX_H_
#include "../common/mem_region.h"
#include "cryobj/symmetric_key.h"
#include "extension_service.h"
#include "crypto_context.h"
#include "../../../core/vector.h"
#include "../../../core/utility.h"
#include "../../../core/result.h"
#include "cryobj/secret_seed.h"
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <memory> 
namespace ara{
    namespace crypto{
        namespace cryp{
            class RandomGeneratorCtx : public CryptoContext
            {
            public:
            
                using Uptr = std::unique_ptr<RandomGeneratorCtx>;

                //pure virtual functions
                virtual bool AddEntropy (ReadOnlyMemRegion entropy) noexcept=0;

                virtual ara::core::Result< ara::core::Vector<ara::core::Byte> > Generate (std::uint32_t count) noexcept=0;

               // virtual ExtensionService::Uptr GetExtensionService () const noexcept=0;

                virtual bool Seed (ReadOnlyMemRegion seed) noexcept=0;
                
                //virtual bool Seed (const SecretSeed &seed) noexcept=0;
                
                virtual bool SetKey (const SymmetricKey &key) noexcept=0;
            };
        }
    }
}

#endif /* RANDOM_GENERATOR_CTX_H_ */
