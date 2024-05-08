#ifndef CRYPTOPP_CHACHA_Stream_CIPHER_CTX_H
#define CRYPTOPP_CHACHA_Stream_CIPHER_CTX_H

#include "../../private/cryp/stream_cipher_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include "cryobj/cryptopp_aes_128_symmetric_key.h"
#include "cryptopp/chacha.h"
#include "cryptopp/osrng.h"
#include "../../helper/state.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CHACHA_StreamCipherCtx : public StreamCipherCtx
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 1;


            private:
                /*****************  attributes **********************/
                CryptoPP_AES_128_SymmetricKey *mKey;
                CryptoTransform  mTransform;
                CryptoPP_CryptoPrimitiveId mPId;
                helper::setKeyState mSetKeyState;    
                helper::calling mCallState;      
                std::string data_context;
                CryptoPP::byte iv[8];

                
            public:
                //using Uptr = std::unique_ptr<CryptoPP_AES_SymmetricBlockCipherCtx>;

                /***************** constructor **********************/     
                CryptoPP_CHACHA_StreamCipherCtx();


                
                ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept override;
                
                /****** override pure virtual functions related to CryptoContext *****/
                // Return CryptoPrimitivId instance containing instance identification
                CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                /*
                    Check if the crypto context is already initialized and ready to use. 
                    It checks all required values, including: key value, IV/seed, etc
                */
                bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related SymmetricBlockCipherCtx *****/
                // takes key and type of processing we want (type of operation ex:Encryption or decryption)
                ara::core::Result<void> SetKey( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                      ) noexcept override;
                
                //  takes the data that we want to process (preform an operation on it)
                ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks(ReadOnlyMemRegion in) noexcept override;

                //  takes the data that we want to process (preform an operation on it)
                ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBytes(ReadOnlyMemRegion in) noexcept override;


                ara::core::Result<ara::core::Vector<ara::core::Byte> > FinishBytes(ReadOnlyMemRegion in) noexcept override;



                /*
                    Get the kind of transformation configured for this context: kEncrypt or kDecrypt
                    returns CryptoErrorDomain::kUninitialized Context,if SetKey() has not been called yet
                */
                virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept override;
                
                
            
            };
        }
    }
}

#endif