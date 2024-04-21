#include "cryptopp_rsa_2046_decryptor_private_ctx.h"
#include "../../private/common/crypto_error_domain.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {   
            extern CryptoErrorDomain _obj;

            const std::string CryptoPP_RSA_DecryptorPrivateCtx::mAlgName("rsa_2046");

            /***************** constructor **********************/
            
            CryptoPP_RSA_DecryptorPrivateCtx::CryptoPP_RSA_DecryptorPrivateCtx(): mKey(nullptr),
                                                                                  mPId(mAlgId,mAlgName),
                                                                                  mSetKeyState(helper::setKeyState::NOT_CALLED)
            {}
            


            /****** override pure virtual functions related to CryptoContext *****/

            /*
                Return CryptoPrimitivId instance containing instance identification
            */
           
            CryptoPrimitiveId::Uptr CryptoPP_RSA_DecryptorPrivateCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
            */
           
            bool CryptoPP_RSA_DecryptorPrivateCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }
            

            
            
            /***** override pure virtual functions inherited related SymmetricBlockCipherCtx *****/
            
            ara::core::Result<ara::core::Vector<ara::core::Byte> > CryptoPP_RSA_DecryptorPrivateCtx::ProcessBlock ( ReadOnlyMemRegion in,
                                                                                  bool suppressPadding
                                                                                ) const noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED)
                {   
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,5); 
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(x);
                }

                try 
                {
                    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(mKey->getKey());

                    std::string cipher;                
                    std::string plain(in.begin(), in.end());
                    //std::cout << "Input Data: " << plain << std::endl;

                    // Initialize a random number generator
                    CryptoPP::AutoSeededRandomPool prng;

                    CryptoPP::StringSource( plain,
                                true,
                                new CryptoPP::PK_DecryptorFilter(prng, decryptor, new CryptoPP::StringSink(cipher))
                                );

                    ara::core::Vector<ara::core::Byte> decryptedData(cipher.begin(), cipher.end());
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(decryptedData);
                } 
                catch (const CryptoPP::Exception& e) {
                    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                }
            }

            ara::core::Result<void> CryptoPP_RSA_DecryptorPrivateCtx::SetKey (const PrivateKey &key) noexcept
            {
                try
                {
                    const CryptoPP_RSA_PrivateKey& rsaKey = dynamic_cast<const CryptoPP_RSA_PrivateKey&>(key);
                    mKey = new CryptoPP_RSA_PrivateKey(rsaKey);
                
                    mSetKeyState = helper::setKeyState::CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) {
                    std::cerr << "Failed to cast PrivateKey to CryptoPP_RSA_PrivateKey: " << e.what() << std::endl;
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject,5); 
                    return ara::core::Result<void>::FromError(x);
                }
            }
            


            /*
            ara::core::Result<void> CryptoPP_RSA_DecryptorPrivateCtx::Reset () noexcept
            {

            }
            */
        }
    }
}