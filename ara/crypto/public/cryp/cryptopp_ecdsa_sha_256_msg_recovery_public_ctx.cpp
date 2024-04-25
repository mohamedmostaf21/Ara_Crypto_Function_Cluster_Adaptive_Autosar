#include "cryptopp_ecdsa_sha_256_msg_recovery_public_ctx.h"
#include "../../private/common/crypto_error_domain.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        { 
            const std::string CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::mAlgName("ecdsa");

            /***************** constructor **********************/
            
            CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx(): mKey(nullptr),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(helper::setKeyState::NOT_CALLED)
            {}

            
            /****** override pure virtual functions related to CryptoContext *****/

            /*
                Return CryptoPrimitivId instance containing instance identification
            */
            CryptoPrimitiveId::Uptr CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                Check if the crypto context is already initialized and ready to use. 
                It checks all required values, including: key value, IV/seed, etc
            */
            bool CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }



            /***** override pure virtual functions inherited related MsgRecoveryPublicCtx *****/

            std::size_t CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::GetMaxInputSize (bool suppressPadding) const noexcept
            {
                return 10; // to change in future
            }

            std::size_t CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::GetMaxOutputSize (bool suppressPadding) const noexcept
            {
                return 10; // to change in future
            }

            ara::core::Result<ara::core::Vector<ara::core::Byte> > CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::DecodeAndVerify (ReadOnlyMemRegion in) const noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
                try 
                {
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(mKey->getValue());

                    ara::core::Vector<ara::core::Byte> message(in.begin(), in.begin() + in.size() - 64);
                    ara::core::Vector<ara::core::Byte> signature(in.begin() + in.size() - 64, in.end());

                    bool result = verifier.VerifyMessage( (const CryptoPP::byte*)&message[0], message.size(), (const CryptoPP::byte*)&signature[0], signature.size() );
                    if(result)
                    {
                        std::cout << "verfied\n";
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(message);
                    }
                    else
                    {
                        std::cout << "not verfied\n";
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kAuthTagNotValid, NoSupplementaryDataForErrorDescription));                    
                    }
                } 
                catch (const CryptoPP::Exception& e) {
                    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                }
            }

            
            ara::core::Result<void> CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx::SetKey (const PublicKey &key) noexcept
            {
                try
                {
                    const CryptoPP_ECDSA_SHA_256_PublicKey& ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_SHA_256_PublicKey&>(key);
                    mKey = new CryptoPP_ECDSA_SHA_256_PublicKey(ecdsaKey);
                
                    mSetKeyState = helper::setKeyState::CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast PrivateKey to CryptoPP_ECDSA_PrivateKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));
                }
            }

        }
    }
}
