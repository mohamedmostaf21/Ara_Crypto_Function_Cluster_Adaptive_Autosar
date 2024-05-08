#ifndef CRYPTOPP_ECDSA_SIG_ENCODE_PRIVATE_CTX_H
#define CRYPTOPP_ECDSA_SIG_ENCODE_PRIVATE_CTX_H

#include "../../private/cryp/sig_encode_private_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_ecdsa_sha_256_private_key.h"
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx : public SigEncodePrivateCtx
            {
            public:
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 5;

            private:      
                /*****************  attributes **********************/
                CryptoPP_ECDSA_PrivateKey *mKey;
                CryptoPP_CryptoPrimitiveId mPId;
                helper::setKeyState mSetKeyState;

            public:
                /***************** constructor **********************/
                CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx();

                /****** override pure virtual functions related to CryptoContext *****/
                //  Return CryptoPrimitivId instance containing instance identification
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related SigEncodePrivateCtx *****/
                std::size_t GetMaxInputSize (bool suppressPadding=false) const noexcept override;

                std::size_t GetMaxOutputSize (bool suppressPadding=false) const noexcept override;

                ara::core::Result<void> SetKey (const PrivateKey &key) noexcept override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > SignAndEncode (ReadOnlyMemRegion in) const noexcept override;


                // ExtensionService::Uptr GetExtensionService () const noexcept=0;

                //ara::core::Result<void> Reset () noexcept override;
            };
        }
    }
}

#endif