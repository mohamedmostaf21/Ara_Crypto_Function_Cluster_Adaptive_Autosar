#include "cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "../../private/common/crypto_error_domain.h"
#include "cryobj/cryptopp_hmac_sha_256_signature.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {    
            const std::string CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::mAlgName("hmac_sha_256");
            
            /********************** constructor **************************/
                
            CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx():
                                                            mKey(nullptr),
                                                            mTransform(CryptoTransform::kMacGenerate),
                                                            mPId(mAlgId,mAlgName),
                                                            mSetKeyState(helper::setKeyState::NOT_CALLED),
                                                            seq{helper::calling::START_IS_NOT_CALLED}
            {
                
            }

            /****** override pure virtual functions related to CryptoContext *****/

            CryptoPrimitiveId::Uptr CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::GetCryptoPrimitiveId () const noexcept
            {
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }

            bool CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::IsInitialized () const noexcept
            {
                return true;
            }


            /***** override pure virtual functions inherited related MessageAuthnCodeCtx *****/

            // DigestService::Uptr GetDigestService () const noexcept=0;

            ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::SetKey ( const SymmetricKey &key, 
                                                CryptoTransform transform) noexcept
            {
                if( transform != CryptoTransform::kMacGenerate && 
                    transform != CryptoTransform::kMacVerify) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUsageViolation, NoSupplementaryDataForErrorDescription));
                }

                try
                {
                    const CryptoPP_HMAC_SHA_256_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_HMAC_SHA_256_SymmetricKey&>(key);
                    mKey = new CryptoPP_HMAC_SHA_256_SymmetricKey(aesKey);
                    hmac.SetKey(mKey->getValue(), mKey->getValue().size());

                    mTransform = transform;
                    mSetKeyState = helper::setKeyState::CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Start (ReadOnlyMemRegion iv) noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
                else if(iv.empty()) // no IV is passed
                {
                    seq = helper::calling::START_IS_CALLED;

                    hmac.Restart();
                    return ara::core::Result<void>::FromValue();
                }
                else // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnsupported, NoSupplementaryDataForErrorDescription));
                }
            }

            // ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Start (const SecretSeed &iv) noexcept=0;

            /*
            ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Update (const RestrictedUseObject &in) noexcept
            {

            }
            */

            ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Update (ReadOnlyMemRegion in) noexcept
            {
                if(seq == helper::calling::START_IS_NOT_CALLED) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }

                seq = helper::calling::UPDATE_IS_CALLED;
                
                hmac.Update(in.data(), in.size());
                return ara::core::Result<void>::FromValue();
            }

            ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Update (std::uint8_t in) noexcept
            {
                if(seq == helper::calling::START_IS_NOT_CALLED) // return errror
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }

                seq = helper::calling::UPDATE_IS_CALLED;
                
                hmac.Update((const CryptoPP::byte*)&in, sizeof(in));
                return ara::core::Result<void>::FromValue();
            }
            
            ara::core::Result<Signature::Uptrc> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Finish (bool makeSignatureObject) noexcept
            {
                if(seq == helper::calling::START_IS_NOT_CALLED) // return error
                {
                    return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }
                else if(seq == helper::calling::UPDATE_IS_CALLED)
                {
                    seq = helper::calling::FINISH_IS_CALLED;

                    digest.resize(hmac.DigestSize());
                    hmac.Final(digest);

                    if(makeSignatureObject)
                    {
                        auto signature = std::make_unique<CryptoPP_HMAC_SHA256_Signature>();
                        signature->setValue(digest);
                        
                        return ara::core::Result<CryptoPP_HMAC_SHA256_Signature::Uptrc>::FromValue(std::move(signature));
                    }
                    else
                        return ara::core::Result<CryptoPP_HMAC_SHA256_Signature::Uptrc>::FromValue(nullptr);
                }
                else if(seq == helper::calling::FINISH_IS_CALLED)
                {
                    auto signature = std::make_unique<CryptoPP_HMAC_SHA256_Signature>();
                    signature->setValue(digest);
                    
                    return ara::core::Result<Signature::Uptrc>::FromValue(std::move(signature));
                }
                else // return error
                {
                    return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidUsageOrder, NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<ara::core::Vector<ara::core::Byte> > CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::GetDigest (std::size_t offset) const noexcept
            {
                if(seq == helper::calling::FINISH_IS_CALLED)
                {
                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : digest)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }

                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
                }
                else // return error
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<bool> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Check (const Signature &expected) const noexcept
            {
                return ara::core::Result<bool>::FromValue(true);
            }

            //ara::core::Result<void> CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx::Reset () noexcept=0;        
        }
    }
}
