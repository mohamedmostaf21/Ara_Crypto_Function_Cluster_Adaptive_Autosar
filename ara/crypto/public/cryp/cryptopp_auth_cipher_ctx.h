#ifndef CRYPTOPP_AUTH_CIPHER_CTX_H
#define CRYPTOPP_AUTH_CIPHER_CTX_H
#include "../../private/cryp/auth_cipher_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_aes_symmetric_key.h"
#include "cryobj/cryptopp_hmac_sha_256_signature.h"
#include "../../helper/state.h"
#include "../../../core/vector.h"
#include "../../private/cryp/hash_function_ctx.h"
#include "cryptopp/pubkey.h"
#include "cryptopp_sha_256_hash_function_ctx.h"

#include "cryptopp_aes_symmetric_block_cipher_ctx.h"
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            using namespace helper;
            class Cryptopp_AuthCipherCtx : public AuthCipherCtx
            {
                private:
                CryptoPP_CryptoPrimitiveId mPId;
                std::string m_cipher;
                ara::core::Vector<ara::core::Byte> associatedData_;
                bool m_confidentialDataProcessed;
                public:
                /******************* constants **********************/
                static const std::string mAlgName;
                static const CryptoPrimitiveId::AlgId mAlgId{5};
                CryptoPP_AES_SymmetricKey *mKey;
                CryptoTransform  mTransform;
                helper::setKeyState  mSetKeyState;
                CryptoPP::SecByteBlock digest;   
                calling seq;
            
                CryptoPP::HMAC<CryptoPP::SHA256> hmac;
                /******************** Constructour *****************/
                Cryptopp_AuthCipherCtx();
                   
                /****** override pure virtual functions related to CryptoContext *****/

                /*
                    Return CryptoPrimitivId instance containing instance identification
                */
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                virtual bool IsInitialized () const noexcept override;

                /******************** APIs **************************/
                virtual ara::core::Result<bool> Check (const Signature &expected) const noexcept override;

               // virtual DigestService::Uptr GetDigestService () const noexcept override; to do
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte>> GetDigest(std::size_t offset=0)const noexcept override;
                virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept override;

                virtual std::uint64_t GetMaxAssociatedDataSize () const noexcept override;

                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessConfidentialData (ReadOnlyMemRegion in,
                                                                                                        ara::core::Optional<ReadOnlyMemRegion> expectedTag
                                                                                                    ) noexcept override;

                // virtual ara::core::Result<void> ProcessConfidentialData(ReadWriteMemRegion inOut,
                //                                                         ara::core::Optional<ReadOnlyMemRegion> expectedTag
                //                                                     )noexcept=0;

                //virtual ara::core::Result<void> Reset () noexcept override;
                
                virtual ara::core::Result<void> SetKey ( const SymmetricKey &key,
                                                        CryptoTransform transform = CryptoTransform::kEncrypt
                                                    ) noexcept override;

                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept override;

                // virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept override;

                // virtual ara::core::Result<void> UpdateAssociatedData (const RestrictedUseObject &in) noexcept override;

                virtual ara::core::Result<void> UpdateAssociatedData(ReadOnlyMemRegion in) noexcept override;

                virtual ara::core::Result<void> UpdateAssociatedData (std::uint8_t in) noexcept override;
                ara::core::Result<void>  Update (ReadOnlyMemRegion in) noexcept;
                bool VerifyTag(const std::span<const unsigned char>& expectedTag);
                ara::core::Result<ara::core::Vector<ara::core::Byte>> ProcessData ( ReadOnlyMemRegion in,
                                                                                        bool suppressPadding=false
                                                                                        ) const noexcept;
                 ara::core::Result<Signature::Uptrc> Finish(bool makeSignatureObject=false) noexcept;
                std::string ToString(const CryptoTransform& transform) const;
               

            };
        }
    }
}
#endif /* CRYPTOPP_AUTH_CIPHER_CTX_H */


