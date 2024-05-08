#include "cryptopp_rsa_2046_encryptor_public_ctx.h"
#include "../../private/common/crypto_error_domain.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            const std::string CryptoPP_RSA_EncryptorPublicCtx::mAlgName("rsa_2046");

            /***************** constructor **********************/
            
            CryptoPP_RSA_EncryptorPublicCtx::CryptoPP_RSA_EncryptorPublicCtx(): mKey(nullptr),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(helper::setKeyState::NOT_CALLED)
            {}



            /****** override pure virtual functions related to CryptoContext *****/
            /*
                Return CryptoPrimitivId instance containing instance identification
            */
            CryptoPrimitiveId::Uptr CryptoPP_RSA_EncryptorPublicCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
            */
            bool CryptoPP_RSA_EncryptorPublicCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }

            

            /***** override pure virtual functions inherited related EncryptorPublicCtx *****/

            ara::core::Result<ara::core::Vector<ara::core::Byte> > CryptoPP_RSA_EncryptorPublicCtx::ProcessBlock ( ReadOnlyMemRegion in,
                                                                                  bool suppressPadding
                                                                                ) const noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
                else if(!in.size())
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    if(suppressPadding && in.size() != 2046)
                    {
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                    }
                    else
                    {
                        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(mKey->getValue());

                        std::string outputString;                
                        std::string inputString(in.begin(), in.end());
                        //std::cout << "Input Data: " << plain << std::endl;

                        // Initialize a random number generator
                        CryptoPP::AutoSeededRandomPool prng;

                        CryptoPP::StringSource( 
                                inputString,
                                true,
                                new CryptoPP::PK_EncryptorFilter(prng, encryptor, new CryptoPP::StringSink(outputString))
                        );

                        ara::core::Vector<ara::core::Byte> outputVector(outputString.begin(), outputString.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(outputVector);
                    }
                }
            }

            ara::core::Result<void> CryptoPP_RSA_EncryptorPublicCtx::SetKey (const PublicKey &key) noexcept
            {
                try
                {
                    const CryptoPP_RSA_2046_PublicKey& rsaKey = dynamic_cast<const CryptoPP_RSA_2046_PublicKey&>(key);
                    mKey = new CryptoPP_RSA_2046_PublicKey(rsaKey);
                
                    mSetKeyState = helper::setKeyState::CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast PublicKey to CryptoPP_RSA_PublicKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));
                }
            }
            
            /*
            ara::core::Result<void> CryptoPP_RSA_EncryptorPublicCtx::Reset () noexcept
            {

            }
            */
        }
    }
}