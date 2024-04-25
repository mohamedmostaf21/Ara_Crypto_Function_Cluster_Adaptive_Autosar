#include "cryptopp_ecdsa_sha_256_sig_encode_private_ctx.h"
#include "../../private/common/crypto_error_domain.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        { 
            const std::string CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::mAlgName("ecdsa");

            /***************** constructor **********************/
            
            CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx(): mKey(nullptr),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(helper::setKeyState::NOT_CALLED)
            {}

            
            /****** override pure virtual functions related to CryptoContext *****/

            /*
                Return CryptoPrimitivId instance containing instance identification
            */
            CryptoPrimitiveId::Uptr CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                Check if the crypto context is already initialized and ready to use. 
                It checks all required values, including: key value, IV/seed, etc
            */
            bool CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }



            /***** override pure virtual functions inherited related SigEncodePrivateCtx *****/

            std::size_t CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::GetMaxInputSize (bool suppressPadding) const noexcept
            {
                return 10; // to change in future
            }

            std::size_t CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::GetMaxOutputSize (bool suppressPadding) const noexcept
            {
                return 10; // to change in future
            }

            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::SignAndEncode (ReadOnlyMemRegion in) const noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
                try 
                {
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(mKey->getValue());

                    std::string plain(in.begin(), in.end());
                    //std::cout << "Input Data: " << plain << std::endl;

                    // Initialize a random number generator
                    CryptoPP::AutoSeededRandomPool prng;

                    // Allocate a string for both message and signature
                    std::string messageSignature = plain;
                    messageSignature.resize(plain.size() + 64);

                    // Sign the message and append the signature to the end of the message data
                    signer.SignMessage(prng, (const CryptoPP::byte*)plain.data(), plain.size(), (CryptoPP::byte*)(messageSignature.data() + plain.size()));
                    messageSignature.resize(plain.size() + 64);

                    ara::core::Vector<ara::core::Byte> dataVector(messageSignature.begin(), messageSignature.end());
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(dataVector);
                } 
                catch (const CryptoPP::Exception& e) {
                    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                }
            }

            ara::core::Result<void> CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx::SetKey (const PrivateKey &key) noexcept
            {
                try
                {
                    const CryptoPP_ECDSA_PrivateKey& ecdsaKey = dynamic_cast<const CryptoPP_ECDSA_PrivateKey&>(key);
                    mKey = new CryptoPP_ECDSA_PrivateKey(ecdsaKey);
                
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
