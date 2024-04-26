#include "cryptopp_chacha_stream_cipher_ctx.h"
#include "cryptopp/chachapoly.h"
#include "../../private/common/crypto_error_domain.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rijndael.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            const std::string CryptoPP_CHACHA_StreamCipherCtx::mAlgName("AES_CHA_CHA");


            /***************** constructor **********************/         
            CryptoPP_CHACHA_StreamCipherCtx::CryptoPP_CHACHA_StreamCipherCtx(): mKey(nullptr),
                                                    mTransform(CryptoTransform::kEncrypt),
                                                    mPId(mAlgId,mAlgName),
                                                    mSetKeyState(helper::setKeyState::NOT_CALLED),
                                                    mCallState(helper::calling::START_IS_NOT_CALLED)
            {
                
            }




            /****** override pure virtual functions related to CryptoContext *****/

            
            // Return CryptoPrimitivId instance containing instance identification
            CryptoPrimitiveId::Uptr CryptoPP_CHACHA_StreamCipherCtx::GetCryptoPrimitiveId () const noexcept
            {                    
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }

            ara::core::Result<void> CryptoPP_CHACHA_StreamCipherCtx::Start(ReadOnlyMemRegion iv) noexcept
            {       
                if(mSetKeyState == helper::setKeyState::NOT_CALLED)
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
                else if(iv.empty())
                {
                    CryptoPP::AutoSeededRandomPool prng;

                    prng.GenerateBlock(this->iv, sizeof(this->iv));

                    mCallState = helper::calling::START_IS_CALLED;

                    return ara::core::Result<void>();
                }
                else
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnsupported, NoSupplementaryDataForErrorDescription));
                }
            }


            /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
            */
            bool CryptoPP_CHACHA_StreamCipherCtx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mCallState == helper::calling::START_IS_CALLED && mKey != nullptr);
            }
            



            /*
                takes key and type of processing we want (type of operation ex:Encryption or decryption)
            */
            ara::core::Result<void> CryptoPP_CHACHA_StreamCipherCtx::SetKey( const SymmetricKey &key,
                                                    CryptoTransform transform
                                                    ) noexcept
            {  
                if(transform != CryptoTransform::kEncrypt && 
                    transform != CryptoTransform::kDecrypt) // return error
                {
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUsageViolation, NoSupplementaryDataForErrorDescription));
                }

                try
                {    
                    if(mSetKeyState == helper::setKeyState::NOT_CALLED)
                    {
                        const CryptoPP_SymmetricKey& Key = dynamic_cast<const CryptoPP_SymmetricKey&>(key);
                        mKey = new CryptoPP_SymmetricKey(Key);
                        
                        mSetKeyState = helper::setKeyState::CALLED;
                    }
                    mTransform = transform;

                    data_context.erase();
                    return ara::core::Result<void>::FromValue();
                }
                catch (const std::bad_cast& e) // return error
                {
                    // Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey
                    return ara::core::Result<void>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));
                }
            }



            /* 
                takes the data that we want to process (preform an operation on it)
                returns CryptoErrorDomain::kUninitializedContext,if SetKey() has not been called yet
            */                
             ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_CHACHA_StreamCipherCtx::ProcessBlocks( ReadOnlyMemRegion in
                                                                                            ) noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED || mCallState == helper::calling::START_IS_NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }
                else if(mCallState == helper::calling::UPDATE_IS_CALLED)
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidUsageOrder, NoSupplementaryDataForErrorDescription));
                }
                else if(!in.size())
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                }
                if(mTransform == CryptoTransform::kEncrypt)
                    {
                        CryptoPP::ChaCha::Encryption encryptor;
                        encryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;

                        std::string plain(in.begin(), in.end());
                        std::cout << "Input Data: " << plain << std::endl;

                        std::string cipher;
                        CryptoPP::StringSource(plain, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                    }
                    else 
                    {
                        CryptoPP::ChaCha::Decryption decryptor;
                        decryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;
                
                        std::string cipher(in.begin(), in.end());
                        //std::cout << "Input Data Cipher: " << cipher << std::endl;

                        std::string plain;
                        CryptoPP::StringSource(cipher, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(plain)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> decryptedData(plain.begin(), plain.end());
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(decryptedData);
                    }
            }     

            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_CHACHA_StreamCipherCtx::ProcessBytes( ReadOnlyMemRegion in
                                                                                            ) noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED || mCallState == helper::calling::START_IS_NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }
                else if(!in.size())
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                }
                if(mTransform == CryptoTransform::kEncrypt)
                    {
                        CryptoPP::ChaCha::Encryption encryptor;
                        encryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;

                        std::string plain(in.begin(), in.end());

                        data_context = data_context + plain;
                        std::cout << "Input Data: " << data_context << std::endl;

                        std::string cipher;
                        CryptoPP::StringSource(data_context, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());

                        mCallState == helper::calling::UPDATE_IS_CALLED;
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                    }
                    else 
                    {
                        CryptoPP::ChaCha::Decryption decryptor;
                        decryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;
                
                        std::string cipher(in.begin(), in.end());
                        //std::cout << "Input Data Cipher: " << cipher << std::endl;

                        data_context = data_context + cipher;

                        std::string plain;
                        CryptoPP::StringSource(data_context, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(plain)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> decryptedData(plain.begin(), plain.end());

                        mCallState = helper::calling::UPDATE_IS_CALLED;
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(decryptedData);
                    }
            }        

            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_CHACHA_StreamCipherCtx::FinishBytes( ReadOnlyMemRegion in
                                                                                            ) noexcept
            {
                if(mSetKeyState == helper::setKeyState::NOT_CALLED || mCallState == helper::calling::START_IS_NOT_CALLED) // return error
                {   
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted, NoSupplementaryDataForErrorDescription));
                }
                else if(!in.size())
                {
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                }
                if(mTransform == CryptoTransform::kEncrypt)
                    {
                        CryptoPP::ChaCha::Encryption encryptor;
                        encryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;

                        std::string plain(in.begin(), in.end());

                        data_context = data_context + plain;
                        std::cout << "Input Data: " << data_context << std::endl;

                        std::string cipher;
                        CryptoPP::StringSource(data_context, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::StringSink(cipher)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> encryptedData(cipher.begin(), cipher.end());
                        data_context.erase();
                        mCallState = helper::calling::FINISH_IS_CALLED;
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(encryptedData);
                    }
                    else 
                    {
                        CryptoPP::ChaCha::Decryption decryptor;
                        decryptor.SetKeyWithIV(mKey->getValue(), mKey->getValue().size(), iv);
                        //std::cout << "Key: " << bytes_to_hex(mKey->getKey(), mKey->getKey().size()) << std::endl;
                
                        std::string cipher(in.begin(), in.end());
                        //std::cout << "Input Data Cipher: " << cipher << std::endl;

                        data_context = data_context + cipher;

                        std::string plain;
                        CryptoPP::StringSource(data_context, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::StringSink(plain)));
                        //std::cout << "Cipher Text: " << bytes_to_hex((const uint8_t*)cipher.data(), cipher.size()) << std::endl;
                        //std::cout << "Cipher Text: " << cipher << std::endl;

                        ara::core::Vector<ara::core::Byte> decryptedData(plain.begin(), plain.end());
                        data_context.erase();
                        mCallState = helper::calling::FINISH_IS_CALLED;
                        return ara::core::Result<ara::core::Vector<ara::core::Byte>>(decryptedData);
                    }
            }              



            /*
                Get the kind of transformation configured for this context: kEncrypt or kDecrypt
                returns CryptoErrorDomain::kUninitializedContext,if SetKey() has not been called yet
            */
            ara::core::Result<CryptoTransform> CryptoPP_CHACHA_StreamCipherCtx::GetTransformation () const noexcept
            {
                if(mSetKeyState == helper::setKeyState::CALLED)
                    return ara::core::Result<CryptoTransform>(mTransform);
                else // return error
                {
                    return ara::core::Result<CryptoTransform>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUninitializedContext, NoSupplementaryDataForErrorDescription));
                }
            }
            



            // CryptoService::Uptr GetCryptoService () const noexcept=0;
                                            
            // ara::core::Result<void> Reset () noexcept=0;
        }
    }
}