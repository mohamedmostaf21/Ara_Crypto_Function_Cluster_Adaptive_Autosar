#ifndef CRYPTOPP_SHA_256_HASH_FUNCTION_CTX_H
#define CRYPTOPP_SHA_256_HASH_FUNCTION_CTX_H

#include "../../private/cryp/hash_function_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_SHA_256_HashFunctionCtx: public HashFunctionCtx 
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                static const CryptoPrimitiveId::AlgId mAlgId{1};

            
            private:
                /***************************** attributes *******************/
                CryptoPP::SHA256 hash;
                CryptoPP::SecByteBlock digest;   
                CryptoPP_CryptoPrimitiveId mPId;
                helper::calling seq;

            public:  
                /********************** constructor **************************/  
                CryptoPP_SHA_256_HashFunctionCtx();


                /****** override pure virtual functions related to CryptoContext *****/
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related HashFunctionCtx *****/
                ara::core::Result<void> Start () noexcept override;

                ara::core::Result<void> Start (ReadOnlyMemRegion iv) noexcept override;

                // ara::core::Result<void> Start (const SecretSeed &iv) noexcept;

                ara::core::Result<void> Update (std::uint8_t in) noexcept override;

                ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > Finish() noexcept override;
                
                ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest(std::size_t offset=0) noexcept override;
            

                // DigestService::Uptr GetDigestService () const noexcept;

                // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept;
            };
        }
    }
}

#endif