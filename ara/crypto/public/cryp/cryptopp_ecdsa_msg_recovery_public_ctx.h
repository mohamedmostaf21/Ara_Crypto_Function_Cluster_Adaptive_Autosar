#ifndef CRYPTOPP_ECDSA_MSG_RECOVERY_PUBLIC_CTX_H     
#define CRYPTOPP_ECDSA_MSG_RECOVERY_PUBLIC_CTX_H

#include "../../private/cryp/msg_recovery_public_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_ecdsa_public_key.h"
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_ECDSA_MsgRecoveryPublicCtx : public MsgRecoveryPublicCtx
            {
            public:
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 5;

            private:      
                /*****************  attributes **********************/
                CryptoPP_ECDSA_PublicKey *mKey;
                CryptoPP_CryptoPrimitiveId mPId;
                helper::setKeyState mSetKeyState;

            public:
                /***************** constructor **********************/
                CryptoPP_ECDSA_MsgRecoveryPublicCtx();


                /****** override pure virtual functions related to CryptoContext *****/    
                /*
                    Return CryptoPrimitivId instance containing instance identification
                */
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                bool IsInitialized () const noexcept override;

                

                //virtual ExtensionService::Uptr GetExtensionService () const noexcept=0;

                std::size_t GetMaxInputSize (bool suppressPadding=false) const noexcept override;
                
                std::size_t GetMaxOutputSize (bool suppressPadding=false) const noexcept override;

                ara::core::Result<void> SetKey (const PublicKey &key) noexcept override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > DecodeAndVerify (ReadOnlyMemRegion in) const noexcept override;

                //virtual ara::core::Result<void> Reset () noexcept override;
            };
        }
    }
}

#endif