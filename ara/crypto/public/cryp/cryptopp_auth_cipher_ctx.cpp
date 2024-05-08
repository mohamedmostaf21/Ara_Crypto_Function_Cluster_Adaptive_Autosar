#include "cryptopp_auth_cipher_ctx.h"
#include "../../private/common/crypto_error_domain.h"
#include <span>
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            const std::string Cryptopp_AuthCipherCtx::mAlgName("Authentication_Cipher");
            Cryptopp_AuthCipherCtx::Cryptopp_AuthCipherCtx () : AuthCipherCtx(),
                                                                mKey(nullptr),
                                                                mTransform(CryptoTransform::kEncrypt),
                                                                mPId(mAlgId,mAlgName),
                                                                mSetKeyState(helper::setKeyState::NOT_CALLED),
                                                                seq{calling::START_IS_NOT_CALLED},
                                                                m_confidentialDataProcessed{false}
                                                                
            {
                   
            }


            /*
                Return CryptoPrimitivId instance containing instance identification
            */
            CryptoPrimitiveId::Uptr Cryptopp_AuthCipherCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
    
            /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
            */
            bool Cryptopp_AuthCipherCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }

            ara::core::Result<bool> Cryptopp_AuthCipherCtx::Check (const Signature &expected) const noexcept
            {
                 // Assuming 'digest' is a member variable that stores the calculated MAC
                // Compare the expected tag with the calculated one
                // If they are equal, return true, else return false
                CryptoPP_HMAC_SHA256_Signature& expectedSign = (CryptoPP_HMAC_SHA256_Signature&)expected;
            
                return (expectedSign.GetDigestValue() == digest ) ? ara::core::Result<bool>::FromValue(true) : ara::core::Result<bool>::FromValue(false);
            }
           
            ara::core::Result<ara::core::Vector<ara::core::Byte>> Cryptopp_AuthCipherCtx::GetDigest (std::size_t offset) const noexcept
            {
                if(seq == calling::FINISH_IS_CALLED)
                {
                    if(offset >= digest.size()){
                        return ara::core::Vector<ara::core::Byte>();
                    }
                    ara::core::Vector<ara::core::Byte> result(digest.begin() + offset, digest.end());
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
                }
                else
                {
                
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotFinished,NoSupplementaryDataForErrorDescription));
                }
            }



            ara::core::Result<CryptoTransform> Cryptopp_AuthCipherCtx::GetTransformation () const noexcept
            {
                if(mSetKeyState == helper::setKeyState::CALLED)
                    return ara::core::Result<CryptoTransform>(mTransform);
                else
                {
                  
                    return ara::core::Result<CryptoTransform>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<void> Cryptopp_AuthCipherCtx::SetTransformation (CryptoTransform transfrom)  noexcept
            {
                if(mSetKeyState == helper::setKeyState::CALLED){
                    this->mTransform = transfrom;
                    this->m_confidentialDataProcessed = false;
                    return ara::core::Result<void>();

                }
                else
                {
                  
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<void> Cryptopp_AuthCipherCtx::SetKey ( const SymmetricKey &key, CryptoTransform transform) noexcept
            {
                if( transform != CryptoTransform::kMacGenerate && 
                    transform != CryptoTransform::kMacVerify &&   transform != CryptoTransform::kEncrypt) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUsageViolation,NoSupplementaryDataForErrorDescription));
                }

                try
                {
                    const CryptoPP_AES_128_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_AES_128_SymmetricKey&>(key);
                    mKey = new CryptoPP_AES_128_SymmetricKey(aesKey);
                    hmac.SetKey(mKey->getValue(), mKey->getValue().size());

                    mTransform = transform;
                    mSetKeyState = helper::setKeyState::CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject,NoSupplementaryDataForErrorDescription));
                }

            }
            
            ara::core::Result<void> Cryptopp_AuthCipherCtx::UpdateAssociatedData (std::uint8_t in) noexcept {
                this->associatedData_.push_back(in);

                auto result = Update(this->associatedData_);

                if( result != ara::core::Result<void>::FromValue()){
                    //return error
                    return result;
                }

                return ara::core::Result<void>::FromValue();
            }

            ara::core::Result<void> Cryptopp_AuthCipherCtx::UpdateAssociatedData (ReadOnlyMemRegion in) noexcept {
                auto result = Update(in);

                if( result != ara::core::Result<void>::FromValue()){
                    //return error
                    return result;
                }

                return ara::core::Result<void>::FromValue();
            }

            std::uint64_t Cryptopp_AuthCipherCtx::GetMaxAssociatedDataSize () const noexcept{
                return this->associatedData_.max_size();
            }

            ara::core::Result<void> Cryptopp_AuthCipherCtx::Start (ReadOnlyMemRegion iv) noexcept{
             
                if(mSetKeyState == helper::setKeyState::NOT_CALLED) // return error
                {
                      
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext,NoSupplementaryDataForErrorDescription));
                }
                else if(iv.empty()) // no IV is passed
                {
                    
                    if(iv.size() < this->associatedData_.size()){
                        
                         
                        return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize,NoSupplementaryDataForErrorDescription));
                    }
                    
                    seq = helper::calling::START_IS_CALLED;
                    hmac.Restart();
                    
                    return ara::core::Result<void>::FromValue();
                }
               
                else  //  IV is passed
                {
                    if(iv.size() < this->associatedData_.size()){
                        
                        
                        return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize,NoSupplementaryDataForErrorDescription));
                    }
                    
                    seq = helper::calling::START_IS_CALLED;
                    
                    return ara::core::Result<void>::FromValue();
                }

        
                
            }
            // Assuming 'digest' is a member variable that stores the calculated MAC
            bool Cryptopp_AuthCipherCtx::VerifyTag(const core::Span<const unsigned char>& expectedTag) noexcept{
                CryptoPP::SecByteBlock expectedTagBlock(expectedTag.size());
                std::copy(expectedTag.begin(), expectedTag.end(), expectedTagBlock.begin());

                // Check if the sizes are equal first
                if (expectedTagBlock.size() != digest.size()) {
                    return false; // Sizes are different, tags are not equal
                }

                // Compare each byte of the two byte arrays
                for (size_t i = 0; i < digest.size(); ++i) {
                    if (expectedTagBlock[i] != digest[i]) {
                        return false; // Tags are not equal
                    }
                }

                // Tags are equal
                return true;
            }

            ara::core::Result<void> Cryptopp_AuthCipherCtx::Update (ReadOnlyMemRegion in) noexcept
            {  
                if(seq == calling::START_IS_NOT_CALLED)
                {
                    
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,NoSupplementaryDataForErrorDescription));
                }

                seq = calling::UPDATE_IS_CALLED;
                
                hmac.Update(in.data(), in.size());
                return ara::core::Result<void>::FromValue();
            }



            
             ara::core::Result<Signature::Uptrc> Cryptopp_AuthCipherCtx::Finish(bool makeSignatureObject) noexcept
            {
                if(seq == helper::calling::START_IS_NOT_CALLED) // return error
                {
                    return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,NoSupplementaryDataForErrorDescription));
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
                    return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidUsageOrder,NoSupplementaryDataForErrorDescription));
                }
            }




            ara::core::Result<ara::core::Vector<ara::core::Byte>> Cryptopp_AuthCipherCtx::ProcessData(ReadOnlyMemRegion in, bool suppressPadding) const noexcept {
                if (mSetKeyState == helper::setKeyState::NOT_CALLED) {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }

                try {
                    if (mTransform == CryptoTransform::kEncrypt) {
                        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryptor;
                        encryptor.SetKey(mKey->getValue(), mKey->getValue().size());

                        std::string plain(in.begin(), in.end());
                        std::cout << "Input Data: " << plain << std::endl;

                        std::string cipher;
                        CryptoPP::StringSource(plain, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));

                        ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                    } else if (mTransform == CryptoTransform::kDecrypt) {
                        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryptor;
                        decryptor.SetKey(mKey->getValue(), mKey->getValue().size());

                        std::string cipher(in.begin(), in.end());
                        std::cout << "Input Cipher: " << cipher << std::endl;

                        std::string decrypted;
                        CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(decrypted)));

                        ara::core::Vector<ara::core::Byte> decryptedData(decrypted.begin(), decrypted.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(decryptedData);
                    } else {
                        // Invalid transform type

                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnsupportedFormat, NoSupplementaryDataForErrorDescription));
                    }
                } catch (const CryptoPP::Exception& e) {
                    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>(ara::core::Vector<ara::core::Byte>());
                }
            }


           
            //To Do
            ara::core::Result<ara::core::Vector<ara::core::Byte> > Cryptopp_AuthCipherCtx::ProcessConfidentialData (ReadOnlyMemRegion in, ara::core::Optional<ReadOnlyMemRegion> expectedTag) noexcept 
            {
           
                if(this->m_confidentialDataProcessed){
                   std::cout << "Confidential data already processed, can't process asscociated data" << std::endl;
                   return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,NoSupplementaryDataForErrorDescription));
                }
      
                  
                //updata the digest with the confidential data
                auto result = Update(in);
                if(!result){
                    //Error occurred during update
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,NoSupplementaryDataForErrorDescription));
                }
                //if the expected tag provided, verify tha tag
                if(expectedTag.HasValue()){
                    auto tagResult = VerifyTag(expectedTag.Value());

                    if(!tagResult){
                       
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError( ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kAuthTagNotValid,NoSupplementaryDataForErrorDescription));
                    }
                 
                    std::cout << "****** Before processing ******** " << std::endl;
                    associatedData_ = ProcessData(in).Value();
                    std::cout << "****** After Processing ******* " << std::endl;
                }
                this->m_confidentialDataProcessed = true; 
              

                return   ara::core::Result<ara::core::Vector<ara::core::Byte>>(associatedData_);
            }

            std::string Cryptopp_AuthCipherCtx::ToString(const CryptoTransform& transform) const noexcept{
                return (transform == CryptoTransform::kEncrypt) ? "Encrypt" : "Decrypt";
            }
            
        }
    }
}