#ifndef CRYPTO_PROVIDER_H
#define CRYPTO_PROVIDER_H

#include "../../../core/string.h"
#include "hash_function_ctx.h"
#include "message_authn_code_ctx.h"
#include "symmetric_block_cipher_ctx.h"
#include "encryptor_public_ctx.h"
#include "decryptor_private_ctx.h"
#include "msg_recovery_public_ctx.h"
#include "sig_encode_private_ctx.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoProvider 
            {
            public:
                using AlgId = CryptoPrimitiveId::AlgId;
                using Uptr = std::unique_ptr<CryptoProvider>;

                
                virtual AlgId ConvertToAlgId (ara::core::StringView primitiveName) const noexcept=0;

	            virtual ara::core::Result<ara::core::String> ConvertToAlgName (AlgId algId) const noexcept=0;

                virtual ara::core::Result<HashFunctionCtx::Uptr> CreateHashFunctionCtx(AlgId algId) noexcept=0;

                virtual ara::core::Result<MessageAuthnCodeCtx::Uptr> CreateMessageAuthCodeCtx (AlgId algId) noexcept=0;
 
                virtual ara::core::Result<SymmetricBlockCipherCtx::Uptr> CreateSymmetricBlockCipherCtx (AlgId algId) noexcept=0;

                virtual ara::core::Result<EncryptorPublicCtx::Uptr> CreateEncryptorPublicCtx (AlgId algId) noexcept=0;

                virtual ara::core::Result<DecryptorPrivateCtx::Uptr> CreateDecryptorPrivateCtx (AlgId algId) noexcept=0;

                virtual ara::core::Result<MsgRecoveryPublicCtx::Uptr> CreateMsgRecoveryPublicCtx (AlgId algId) noexcept=0;

                virtual ara::core::Result<SigEncodePrivateCtx::Uptr> CreateSigEncodePrivateCtx (AlgId algId) noexcept=0;

             
                virtual ara::core::Result<PrivateKey::Uptrc> GeneratePrivateKey ( AlgId algId, 
																	  AllowedUsageFlags allowedUsage, 
																	  bool isSession=false, 
																	  bool isExportable=false
																	) noexcept=0;

                
                virtual ara::core::Result<SymmetricKey::Uptrc> GenerateSymmetricKey ( AlgId algId, 
																		  AllowedUsageFlags allowedUsage,
																		  bool isSession=true,
																		  bool isExportable=false
																		) noexcept=0;
                

                CryptoProvider& operator= (const CryptoProvider &other)=default;
	
                CryptoProvider& operator= (CryptoProvider &&other)=default;
                
                virtual ~CryptoProvider () noexcept=default;
            };
        }
    }
}

#endif