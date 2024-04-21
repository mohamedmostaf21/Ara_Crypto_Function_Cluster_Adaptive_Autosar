#ifndef CRYPTOPP_RANDOM_GENERATOR_CTX_H
#define CRYPTOPP_RANDOM_GENERATOR_CTX_H
#include "../../private/cryp/random_generator_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h> // for AutoSeededRandomPool
#include <cryptopp/hex.h>    // for HexEncoder
#include <cryptopp/filters.h>    // for StringSink
#include "../../../core/result.h"
#include "cryobj/cryptopp_aes_symmetric_key.h"
#include "../../helper/state.h"
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class Cryptopp_RandomGeneratorctx : public RandomGeneratorCtx
            {
             
                private:
                CryptoPP::AutoSeededRandomPool rng;
                CryptoPP_CryptoPrimitiveId mPId;
                
                public:
                /******************* constants **********************/
                static const std::string mAlgName;
                static const CryptoPrimitiveId::AlgId mAlgId{4};
                CryptoPP_AES_SymmetricKey *mKey;
                helper::setKeyState   mSetKeyState;
                /******************** Constructour *****************/
                Cryptopp_RandomGeneratorctx();

                  /******************** APIs **************************/
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                virtual bool IsInitialized () const noexcept override;
              

                virtual bool AddEntropy (ReadOnlyMemRegion entropy) noexcept override;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > Generate (std::uint32_t count) noexcept override;

                //virtual ExtensionService::Uptr GetExtensionService () const noexcept override;

                virtual bool Seed (ReadOnlyMemRegion seed) noexcept override;
                
                //virtual bool Seed (const SecretSeed &seed) noexcept override;
                
                virtual bool SetKey (const SymmetricKey &key) noexcept override;
                ~Cryptopp_RandomGeneratorctx();

                    
            };
        }
    }
}
#endif /*CRYPTOPP_RANDOM_GENERATOR_CTX_H */