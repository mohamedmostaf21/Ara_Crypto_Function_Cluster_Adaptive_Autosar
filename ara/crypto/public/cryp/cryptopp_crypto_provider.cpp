#include "../../private/common/crypto_error_domain.h"
#include "cryptopp_crypto_provider.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            ara::core::Result<HashFunctionCtx::Uptr> CryptoPP_CryptoProvider::CreateHashFunctionCtx(AlgId algId) noexcept
            {                
                if(algId == 1)
                {
                    /*
                    std::unique_ptr<CryptoPP_SHA_256_HashFunctionCtx> context = std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>();
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::move(context));
                    */
                    
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>());
                }
                else
                {
                    return ara::core::Result<HashFunctionCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }


            ara::core::Result<MessageAuthnCodeCtx::Uptr> CryptoPP_CryptoProvider::CreateMessageAuthCodeCtx (AlgId algId) noexcept
            {
                if(algId == 1)
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>(std::make_unique<CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx>());
                }
                else if(algId == 2)
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>(std::make_unique<CryptoPP_HMAC_SHA_512_MessageAuthnCodeCtx>());
                }
                else
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }

 
            ara::core::Result<SymmetricBlockCipherCtx::Uptr> CryptoPP_CryptoProvider::CreateSymmetricBlockCipherCtx (AlgId algId) noexcept 
            {
                if(algId == 1)
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>(std::make_unique<CryptoPP_AES_SymmetricBlockCipherCtx>());
                }
                else
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }


            ara::core::Result<EncryptorPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateEncryptorPublicCtx (AlgId algId) noexcept
            {
                if(algId == 1)
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>(std::make_unique<CryptoPP_RSA_EncryptorPublicCtx>());
                }
                else
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
          
            ara::core::Result<DecryptorPrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateDecryptorPrivateCtx (AlgId algId) noexcept
            {
                if(algId == 1)
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>(std::make_unique<CryptoPP_RSA_DecryptorPrivateCtx>());
                }
                else
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
            ara::core::Result<MsgRecoveryPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateMsgRecoveryPublicCtx (AlgId algId) noexcept
            {
                if(algId == 1)
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_MsgRecoveryPublicCtx>());
                }
                else
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
            ara::core::Result<SigEncodePrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateSigEncodePrivateCtx (AlgId algId) noexcept
            {
                if(algId == 1)
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_SigEncodePrivateCtx>());
                }
                else
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,5));
                }
            }
          
        }
    }
}