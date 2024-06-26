#ifndef CRYPTOPP_CRYPTO_PROVIDER_H
#define CRYPTOPP_CRYPTO_PROVIDER_H

#include "../../private/cryp/crypto_provider.h"
#include "cryptopp_sha_256_hash_function_ctx.h"
#include "cryptopp_sha_512_hash_function_ctx.h"
#include "cryptopp_hmac_sha_256_message_authn_code_ctx.h"
#include "cryptopp_hmac_sha_512_message_authn_code_ctx.h"
#include "cryptopp_aes_ecb_128_symmetric_block_cipher_ctx.h"
#include "cryptopp_rsa_2046_encryptor_public_ctx.h"
#include "cryptopp_rsa_2046_decryptor_private_ctx.h"
#include "cryptopp_ecdsa_sha_256_sig_encode_private_ctx.h"
#include "cryptopp_ecdsa_sha_256_msg_recovery_public_ctx.h"
#include "cryptopp_aes_cbc_128_symmetric_block_cipher_ctx.h"
#include "cryptopp_chacha_stream_cipher_ctx.h"
#include "cryptopp_auth_cipher_ctx.h"
#include "cryptopp_random_generator_ctx.h"


#define SHA_256_ALG_ID       1
#define SHA_512_ALG_ID       5
#define HMAC_SHA_256_ALG_ID  2
#define HMAC_SHA_512_ALG_ID  6
#define AES_ECB_128_ALG_ID   3
#define RSA_2048_ALG_ID      4
#define ECDSA_SHA_256_ALG_ID 12
#define AES_CBC_128_ALG_ID   7
#define CHA_CHA_ALG_ID       8
#define AUTH_CIPHER_ALG_ID          9
#define RANDOM_GENERATOR_ALG_ID     10
#define SIGNATURE_CREATION_ALG_ID   11

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CryptoProvider : public CryptoProvider
            {
            public: 
                AlgId ConvertToAlgId (ara::core::StringView primitiveName) const noexcept override;

	            ara::core::Result<ara::core::String> ConvertToAlgName (AlgId algId) const noexcept override;
                            
                ara::core::Result<HashFunctionCtx::Uptr> CreateHashFunctionCtx(AlgId algId) noexcept override;

                ara::core::Result<MessageAuthnCodeCtx::Uptr> CreateMessageAuthCodeCtx (AlgId algId) noexcept override;
 
                ara::core::Result<SymmetricBlockCipherCtx::Uptr> CreateSymmetricBlockCipherCtx (AlgId algId) noexcept override;

                ara::core::Result<EncryptorPublicCtx::Uptr> CreateEncryptorPublicCtx (AlgId algId) noexcept override;

                ara::core::Result<DecryptorPrivateCtx::Uptr> CreateDecryptorPrivateCtx (AlgId algId) noexcept override;

                ara::core::Result<MsgRecoveryPublicCtx::Uptr> CreateMsgRecoveryPublicCtx (AlgId algId) noexcept override;

                ara::core::Result<SigEncodePrivateCtx::Uptr> CreateSigEncodePrivateCtx (AlgId algId) noexcept override;

                ara::core::Result<StreamCipherCtx::Uptr> CreateStreamCipherCtx (AlgId algId) noexcept override;

                ara::core::Result<Signature::Uptrc> CreateSignature ( AlgId signAlgId,
																  ReadOnlyMemRegion value,
																  const RestrictedUseObject &key,
																  AlgId hashAlgId=kAlgIdNone
																) noexcept override;
		            ara::core::Result<AuthCipherCtx::Uptr> CreateAuthCipherCtx ( AlgId algId) noexcept override;	
                
                ara::core::Result<RandomGeneratorCtx::Uptr> CreateRandomGeneratorCtx ( AlgId algId=kAlgIdDefault,
																				   bool initialize=true
																				 )noexcept override;

                ara::core::Result<PrivateKey::Uptrc> LoadPrivateKey (const IOInterface &container) noexcept override;

                ara::core::Result<PublicKey::Uptrc> LoadPublicKey (const IOInterface &container) noexcept override;

               //ara::core::Result<SecretSeed::Uptrc> LoadSecretSeed (const IOInterface &container) noexcept override;

                ara::core::Result<SymmetricKey::Uptrc> LoadSymmetricKey (const IOInterface &container) noexcept override;
            
                ara::core::Result<PrivateKey::Uptrc> GeneratePrivateKey ( AlgId algId, 
                                                                          AllowedUsageFlags allowedUsage, 
                                                                          bool isSession=false, 
																	      bool isExportable=false
																	) noexcept override;
                
                ara::core::Result<SymmetricKey::Uptrc> GenerateSymmetricKey ( AlgId algId, 
																		  AllowedUsageFlags allowedUsage,
																		  bool isSession=true,
																		  bool isExportable=false
																		) noexcept override;
                                                                
            };
        }
    }
}

#endif
