#ifndef CRYPTOPP_CRYPTO_PROVIDER_H
#define CRYPTOPP_CRYPTO_PROVIDER_H

#include "../../private/cryp/crypto_provider.h"
#include "cryptopp_sha_256_hash_function_ctx.h"
#include "cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "cryptopp_aes_symmetric_block_cipher_ctx.h"
#include "cryptopp_rsa_2046_encryptor_public_ctx.h"
#include "cryptopp_rsa_2046_decryptor_private_ctx.h"
#include "cryptopp_ecdsa_sig_encode_private_ctx.h"
#include "cryptopp_ecdsa_msg_recovery_public_ctx.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CryptoProvider : public CryptoProvider
            {
            public:                             
                ara::core::Result<HashFunctionCtx::Uptr> CreateHashFunctionCtx(AlgId algId) noexcept override;

                ara::core::Result<MessageAuthnCodeCtx::Uptr> CreateMessageAuthCodeCtx (AlgId algId) noexcept override;
 
                ara::core::Result<SymmetricBlockCipherCtx::Uptr> CreateSymmetricBlockCipherCtx (AlgId algId) noexcept override;

                ara::core::Result<EncryptorPublicCtx::Uptr> CreateEncryptorPublicCtx (AlgId algId) noexcept override;

                ara::core::Result<DecryptorPrivateCtx::Uptr> CreateDecryptorPrivateCtx (AlgId algId) noexcept override;

                ara::core::Result<MsgRecoveryPublicCtx::Uptr> CreateMsgRecoveryPublicCtx (AlgId algId) noexcept override;

                ara::core::Result<SigEncodePrivateCtx::Uptr> CreateSigEncodePrivateCtx (AlgId algId) noexcept override;
            };
        }
    }
}

#endif