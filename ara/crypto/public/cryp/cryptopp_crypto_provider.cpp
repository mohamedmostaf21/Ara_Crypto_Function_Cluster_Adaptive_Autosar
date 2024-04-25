#include "../../private/common/crypto_error_domain.h"
#include "cryptopp_crypto_provider.h"


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            CryptoProvider::AlgId CryptoPP_CryptoProvider::ConvertToAlgId (ara::core::StringView primitiveName) const noexcept
            {
                if(primitiveName == "SHA_256_ALG")
                    return SHA_256_ALG_ID;
                else if(primitiveName == "HMAC_SHA_256_ALG")
                    return HMAC_SHA_256_ALG_ID;
                else if(primitiveName == "AES_ECB_128_ALG")
                    return AES_ECB_128_ALG_ID;
                else if(primitiveName == "RSA_2048_ALG")
                    return RSA_2048_ALG_ID;
                else if(primitiveName == "ECDSA_SHA_256_ALG")
                    return ECDSA_SHA_256_ALG_ID;
                else
                    return kAlgIdUndefined;
            }

	        ara::core::Result<ara::core::String> CryptoPP_CryptoProvider::ConvertToAlgName (AlgId algId) const noexcept
            { 
                if(algId == SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("SHA_256_ALG");
                else if(algId == HMAC_SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("HMAC_SHA_256_ALG");
                else if(algId == AES_ECB_128_ALG_ID)
                    return ara::core::Result<ara::core::String>("AES_ECB_128_ALG_ID");
                else if(algId == RSA_2048_ALG_ID)
                    return ara::core::Result<ara::core::String>("RSA_2048_ALG");
                else if(algId == ECDSA_SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("ECDSA_SHA_256_ALG");
                else
                    return ara::core::Result<ara::core::String>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));               
            }   

            ara::core::Result<HashFunctionCtx::Uptr> CryptoPP_CryptoProvider::CreateHashFunctionCtx(AlgId algId) noexcept
            {                
                if(algId == SHA_256_ALG_ID)
                {
                    /*
                    std::unique_ptr<CryptoPP_SHA_256_HashFunctionCtx> context = std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>();
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::move(context));
                    */
                    
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::make_unique<CryptoPP_SHA_256_HashFunctionCtx>());
                }
                else if(algId == SHA_512_ALG_ID)
                {
                    return ara::core::Result<HashFunctionCtx::Uptr>(std::make_unique<CryptoPP_SHA_512_HashFunctionCtx>());
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == AES_ECB_128_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<HashFunctionCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<HashFunctionCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));
                }
            }


            ara::core::Result<MessageAuthnCodeCtx::Uptr> CryptoPP_CryptoProvider::CreateMessageAuthCodeCtx (AlgId algId) noexcept
            {
                if(algId == HMAC_SHA_256_ALG_ID)
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>(std::make_unique<CryptoPP_HMAC_SHA_256_MessageAuthnCodeCtx>());
                }
                else if(algId == HMAC_SHA_512_ALG_ID)
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>(std::make_unique<CryptoPP_HMAC_SHA_512_MessageAuthnCodeCtx>());
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == AES_ECB_128_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<MessageAuthnCodeCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));
                }
            }

 
            ara::core::Result<SymmetricBlockCipherCtx::Uptr> CryptoPP_CryptoProvider::CreateSymmetricBlockCipherCtx (AlgId algId) noexcept 
            {
                if(algId == AES_ECB_128_ALG_ID)
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>(std::make_unique<CryptoPP_AES_ECD_128_SymmetricBlockCipherCtx>());
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));
                }
            }


            ara::core::Result<EncryptorPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateEncryptorPublicCtx (AlgId algId) noexcept
            {
                if(algId == RSA_2048_ALG_ID)
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>(std::make_unique<CryptoPP_RSA_EncryptorPublicCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }
          
          
            ara::core::Result<DecryptorPrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateDecryptorPrivateCtx (AlgId algId) noexcept
            {
                if(algId == RSA_2048_ALG_ID)
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>(std::make_unique<CryptoPP_RSA_DecryptorPrivateCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<DecryptorPrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }
          
            ara::core::Result<MsgRecoveryPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateMsgRecoveryPublicCtx (AlgId algId) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID)
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_SHA_256_MsgRecoveryPublicCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == RSA_2048_ALG_ID
                 )
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<MsgRecoveryPublicCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }
          
            ara::core::Result<SigEncodePrivateCtx::Uptr> CryptoPP_CryptoProvider::CreateSigEncodePrivateCtx (AlgId algId) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID)
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>(std::make_unique<CryptoPP_ECDSA_SHA_256_SigEncodePrivateCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == RSA_2048_ALG_ID
                 )
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }

            ara::core::Result<PrivateKey::Uptrc> CryptoPP_CryptoProvider::GeneratePrivateKey ( AlgId algId, 
                                                                          AllowedUsageFlags allowedUsage, 
                                                                          bool isSession, 
                                                                          bool isExportable
																	) noexcept
            {
                if(algId == ECDSA_SHA_256_ALG_ID)
                {
                    if(allowedUsage == kAllowSignature)
                    {
                        // Create an AutoSeededRandomPool object for random number generation
                        CryptoPP::AutoSeededRandomPool prng;   

                        // Generate private key
                        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey myPrivateKey;
                        myPrivateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());

                        std::unique_ptr<CryptoPP_ECDSA_PrivateKey> ptr = std::make_unique<CryptoPP_ECDSA_PrivateKey>();
                    
                        ptr->setValue(myPrivateKey);

                        return ara::core::Result<PrivateKey::Uptrc>(std::move(ptr));
                    }
                    else
                    {
                      return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }
                else if(algId == RSA_2048_ALG_ID)
                {
                    if(allowedUsage == kAllowDataEncryption)
                    {
                        size_t keyLength = 2048;                     // Specify the key length here

                        CryptoPP::InvertibleRSAFunction parameters;  // Create RSA parameters object
                        CryptoPP::AutoSeededRandomPool prng;   // Create an AutoSeededRandomPool object for random number generation
                        parameters.GenerateRandomWithKeySize(prng, keyLength);  // Generate random RSA parameters with the specified key length

                        CryptoPP::RSA::PrivateKey myPrivateKey(parameters);  // Create RSA private key using the generated parameters

                        
                        std::unique_ptr<CryptoPP_RSA_2046_PrivateKey> ptr = std::make_unique<CryptoPP_RSA_2046_PrivateKey>();
                    
                        ptr->setValue(myPrivateKey);

                        return ara::core::Result<PrivateKey::Uptrc>(std::move(ptr));
                    }
                    else
                    {
                      return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }

            
            ara::core::Result<SymmetricKey::Uptrc> CryptoPP_CryptoProvider::GenerateSymmetricKey ( AlgId algId, 
																		  AllowedUsageFlags allowedUsage,
																		  bool isSession,
																		  bool isExportable
																		) noexcept
            {
                if(algId == AES_ECB_128_ALG_ID)
                {
                    if(allowedUsage == kAllowKdfMaterialAnyUsage)
                    {
                        CryptoPP::AutoSeededRandomPool rng; 
                        CryptoPP::SecByteBlock mySymmetricKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
                        rng.GenerateBlock(mySymmetricKey, mySymmetricKey.size());

                        std::cout << "Random AES key: ";
                        for (size_t i = 0; i < mySymmetricKey.size(); i++) {
                            printf("%02x", mySymmetricKey[i]);
                        }
                        std::cout << std::endl;


                        std::unique_ptr<CryptoPP_AES_128_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_128_SymmetricKey>();
                            
                        ptr->setValue(mySymmetricKey);

                        return ara::core::Result<SymmetricKey::Uptrc>(std::move(ptr));
                    }
                    else
                    {
                      return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }
                else if(algId == HMAC_SHA_256_ALG_ID)
                {
                    if(allowedUsage == kAllowSignature)
                    {
                        CryptoPP::AutoSeededRandomPool rng; 
                        CryptoPP::SecByteBlock mySymmetricKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
                        rng.GenerateBlock(mySymmetricKey, mySymmetricKey.size());

                        std::cout << "Random AES key: ";
                        for (size_t i = 0; i < mySymmetricKey.size(); i++) {
                            printf("%02x", mySymmetricKey[i]);
                        }
                        std::cout << std::endl;


                        std::unique_ptr<CryptoPP_HMAC_SHA_256_SymmetricKey> ptr = std::make_unique<CryptoPP_HMAC_SHA_256_SymmetricKey>();
                            
                        ptr->setValue(mySymmetricKey);

                        return ara::core::Result<SymmetricKey::Uptrc>(std::move(ptr));
                    }
                    else
                    {
                      return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID
                 )
                {
                    return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }                                                            
            
        }
    }
}
