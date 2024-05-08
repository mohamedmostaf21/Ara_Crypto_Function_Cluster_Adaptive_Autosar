#ifndef CRYPTOPP_HMAC_SHA_256_MESSAGE_AUTHN_CTX_H
#define CRYPTOPP_HMAC_SHA_256_MESSAGE_AUTHN_CTX_H

#include "../../private/cryp/message_authn_code_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_hmac_sha_256_symmetric_key.h"
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx: public MessageAuthnCodeCtx 
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                static const CryptoPrimitiveId::AlgId mAlgId{1};

            
            private:
                /***************************** attributes *******************/
                CryptoPP::HMAC<CryptoPP::SHA256> hmac;
                CryptoPP::SecByteBlock digest;   
                CryptoPP_CryptoPrimitiveId mPId;
                helper::calling seq;
                CryptoPP_HMAC_SHA_256_SymmetricKey *mKey;
                CryptoTransform  mTransform;
                helper::setKeyState mSetKeyState;


            public:  
                /********************** constructor **************************/            
                CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx();


                /****** override pure virtual functions related to CryptoContext *****/
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related HashFunctionCtx *****/
                ara::core::Result<void> SetKey ( const SymmetricKey &key, 
                                                 CryptoTransform transform=CryptoTransform::kMacGenerate) noexcept  override;

                ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept  override;

                // ara::core::Result<void> Start (const SecretSeed &iv) noexcept  override;

                // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept  override;

                ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept  override;

                ara::core::Result<void> Update (std::uint8_t in) noexcept override;
                
                ara::core::Result<Signature::Uptrc> Finish (bool makeSignatureObject=false) noexcept  override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest (std::size_t offset=0) const noexcept  override;

                ara::core::Result<bool> Check (const Signature &expected) const noexcept  override;


                // DigestService::Uptr GetDigestService () const noexcept override; 

                // ara::core::Result<void> Reset () noexcept  override;
            };
        }
    }
}

#endif