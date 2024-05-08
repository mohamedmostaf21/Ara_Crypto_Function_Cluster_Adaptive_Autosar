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
                else if(primitiveName == "HMAC_SHA_512_ALG")
                    return HMAC_SHA_512_ALG_ID;
                else if(primitiveName == "AES_ECB_128_ALG")
                    return AES_ECB_128_ALG_ID;
                else if(primitiveName == "AES_CBC_128_ALG")
                    return AES_CBC_128_ALG_ID;
                else if(primitiveName == "RSA_2048_ALG")
                    return RSA_2048_ALG_ID;
                else if(primitiveName == "ECDSA_SHA_256_ALG")
                    return ECDSA_SHA_256_ALG_ID;
                else if(primitiveName == "AUTH_CIPHER_ALG_ID")
                    return AUTH_CIPHER_ALG_ID;
                else if(primitiveName == "RANDOM_GENERATOR_ALG_ID")
                    return RANDOM_GENERATOR_ALG_ID;
                else if(primitiveName == "SIGNATURE_CREATION_ALG_ID")
                    return SIGNATURE_CREATION_ALG_ID;
                else
                    return kAlgIdUndefined;
            }

	        ara::core::Result<ara::core::String> CryptoPP_CryptoProvider::ConvertToAlgName (AlgId algId) const noexcept
            { 
                if(algId == SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("SHA_256_ALG");
                else if(algId == HMAC_SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("HMAC_SHA_256_ALG");
                else if(algId == HMAC_SHA_512_ALG_ID)
                    return ara::core::Result<ara::core::String>("HMAC_SHA_512_ALG");
                else if(algId == AES_ECB_128_ALG_ID)
                    return ara::core::Result<ara::core::String>("AES_ECB_128_ALG_ID");
                else if(algId == AES_CBC_128_ALG_ID)
                    return ara::core::Result<ara::core::String>("AES_CBC_128_ALG_ID");
                else if(algId == RSA_2048_ALG_ID)
                    return ara::core::Result<ara::core::String>("RSA_2048_ALG");
                else if(algId == ECDSA_SHA_256_ALG_ID)
                    return ara::core::Result<ara::core::String>("ECDSA_SHA_256_ALG");
                else if(algId == AUTH_CIPHER_ALG_ID)
                    return ara::core::Result<ara::core::String>("AUTH_CIPHER_ALG_ID");
                else if(algId == RANDOM_GENERATOR_ALG_ID)
                    return ara::core::Result<ara::core::String>("RANDOM_GENERATOR_ALG_ID");
                else if(algId == SIGNATURE_CREATION_ALG_ID)
                    return ara::core::Result<ara::core::String>("SIGNATURE_CREATION_ALG_ID");
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
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == AES_ECB_128_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID || 
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
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
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == AES_ECB_128_ALG_ID || algId == AES_CBC_128_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID  || 
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
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
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>(std::make_unique<CryptoPP_AES_ECB_128_SymmetricBlockCipherCtx>());
                }
                else if(algId == AES_CBC_128_ALG_ID)
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>(std::make_unique<CryptoPP_AES_CBC_128_SymmetricBlockCipherCtx>());
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID || algId == AES_CBC_128_ALG_ID ||
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
                 )
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<SymmetricBlockCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));
                }
            }

               ara::core::Result<StreamCipherCtx::Uptr> CryptoPP_CryptoProvider::CreateStreamCipherCtx (AlgId algId) noexcept 
            {
                if (algId == CHA_CHA_ALG_ID)
                {
                     return ara::core::Result<StreamCipherCtx::Uptr>(std::make_unique<CryptoPP_CHACHA_StreamCipherCtx>());
                }
                
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID || algId == AES_ECB_128_ALG_ID || AES_CBC_128_ALG_ID ||
                     algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
                 )
                {
                    return ara::core::Result<StreamCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<StreamCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier,NoSupplementaryDataForErrorDescription));
                }
            }



            ara::core::Result<EncryptorPublicCtx::Uptr> CryptoPP_CryptoProvider::CreateEncryptorPublicCtx (AlgId algId) noexcept
            {
               if(algId == RSA_2048_ALG_ID)
                {
                    return ara::core::Result<EncryptorPublicCtx::Uptr>(std::make_unique<CryptoPP_RSA_EncryptorPublicCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID || algId == AES_CBC_128_ALG_ID ||
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
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
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == ECDSA_SHA_256_ALG_ID || algId == AES_CBC_128_ALG_ID || 
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
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
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == RSA_2048_ALG_ID || algId == AES_CBC_128_ALG_ID ||
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
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
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID ||
                    algId == RSA_2048_ALG_ID || algId == AES_CBC_128_ALG_ID || 
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID
                 )
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<SigEncodePrivateCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }


            
            ara::core::Result<AuthCipherCtx::Uptr> CryptoPP_CryptoProvider::CreateAuthCipherCtx (AlgId algId) noexcept
            {
                if(algId == AUTH_CIPHER_ALG_ID)
                {
                    return ara::core::Result<AuthCipherCtx::Uptr>(std::make_unique<Cryptopp_AuthCipherCtx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == RSA_2048_ALG_ID  || 
                    algId == ECDSA_SHA_256_ALG_ID ||
                    algId == RANDOM_GENERATOR_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_512_ALG_ID || algId == AES_CBC_128_ALG_ID 
                 )
                {
                    return ara::core::Result<AuthCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<AuthCipherCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }


            
            ara::core::Result<RandomGeneratorCtx::Uptr> CryptoPP_CryptoProvider::CreateRandomGeneratorCtx ( AlgId algId, bool initialize)noexcept 
            {
                if(algId == RANDOM_GENERATOR_ALG_ID)
                {
                    return ara::core::Result<RandomGeneratorCtx::Uptr>(std::make_unique<Cryptopp_RandomGeneratorctx>());
                }
                else if(algId == AES_ECB_128_ALG_ID ||
                    algId == SHA_256_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID ||
                    algId == RSA_2048_ALG_ID  || 
                    algId == ECDSA_SHA_256_ALG_ID ||
                    algId == AUTH_CIPHER_ALG_ID ||
                    algId == SIGNATURE_CREATION_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_512_ALG_ID || algId == AES_CBC_128_ALG_ID 
                 )
                {
                    return ara::core::Result<RandomGeneratorCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription));
                }
                else
                {
                    return ara::core::Result<RandomGeneratorCtx::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
                }
            }
            
            ara::core::Result<Signature::Uptrc> CryptoPP_CryptoProvider::CreateSignature( AlgId signAlgId,
                                                                                          ReadOnlyMemRegion value,
                                                                                          const RestrictedUseObject& key,
                                                                                          AlgId hashAlgId
                                                                                        ) noexcept 
            {
                // Step 1: Check if the provided signAlgId is supported
                if (signAlgId == SIGNATURE_CREATION_ALG_ID) {
                
                    std::unique_ptr<CryptoPP_HMAC_SHA256_Signature> signature = std::make_unique<CryptoPP_HMAC_SHA256_Signature>();
              
                    if (key.GetAllowedUsage() != kAllowKdfMaterialAnyUsage) {
                         
                        return ara::core::Result<Signature::Uptrc>::FromError(
                            ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription)
                        );
                    }
                    // if(signature->GetHashAlgId() != hashAlgId){
                    //      std::cout << "Setteing not Done. " << std::endl;
                    //     return ara::core::Result<Signature::Uptrc>::FromError(
                    //         ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription)
                    //     );
                    // }

                    signature->setValue(CryptoPP::SecByteBlock(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()));
                    if(value.size() < signature->GetDigestValue().size()){

                        return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidInputSize, NoSupplementaryDataForErrorDescription));
                    }
                    


                  
                    return ara::core::Result<Signature::Uptrc>(std::move(signature));
                  
                }

                
                else if (signAlgId == AES_ECB_128_ALG_ID ||
                    signAlgId == SHA_256_ALG_ID ||
                    signAlgId == HMAC_SHA_256_ALG_ID ||
                    signAlgId == RSA_2048_ALG_ID  || 
                    signAlgId == ECDSA_SHA_256_ALG_ID ||
                    signAlgId == AUTH_CIPHER_ALG_ID ||
                    signAlgId == RANDOM_GENERATOR_ALG_ID ||signAlgId == SHA_512_ALG_ID ||
                    signAlgId == HMAC_SHA_512_ALG_ID || signAlgId == AES_CBC_128_ALG_ID 
                    ) 
                {

                    return ara::core::Result<Signature::Uptrc>::FromError(
                        ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidArgument, NoSupplementaryDataForErrorDescription)
                    );
                }

           

                else
                {
                      std::cout << "Setteing Not Done. " << std::endl;
                    return ara::core::Result<Signature::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnknownIdentifier, NoSupplementaryDataForErrorDescription));
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
                else if(algId == AES_ECB_128_ALG_ID || algId == AES_CBC_128_ALG_ID ||
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
                    algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID
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
               if(algId == AES_ECB_128_ALG_ID || algId == AES_CBC_128_ALG_ID || algId == AUTH_CIPHER_ALG_ID || algId == RANDOM_GENERATOR_ALG_ID)
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
                else if(algId == CHA_CHA_ALG_ID)
                {
                    if(allowedUsage == kAllowKdfMaterialAnyUsage)
                    {
                        CryptoPP::AutoSeededRandomPool rng; 
                        CryptoPP::SecByteBlock mySymmetricKey(CryptoPP::ChaCha::DEFAULT_KEYLENGTH);
                        rng.GenerateBlock(mySymmetricKey, mySymmetricKey.size());

                        std::cout << "Random key: ";
                        for (size_t i = 0; i < mySymmetricKey.size(); i++) {
                            printf("%02x", mySymmetricKey[i]);
                        }
                        std::cout << std::endl;


                        std::unique_ptr<CryptoPP_AES_128_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_128_SymmetricKey>();
                            
                        ptr->setValue(mySymmetricKey);

                        return ara::core::Result<SymmetricKey::Uptrc>(std::move(ptr));
                    }
                }
                else if(algId == HMAC_SHA_256_ALG_ID || algId == HMAC_SHA_512_ALG_ID)
                { 
                       std::cout << "Enter \n";
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

                        if(algId == HMAC_SHA_256_ALG_ID)
                        {
                            std::unique_ptr<CryptoPP_HMAC_SHA_256_SymmetricKey> ptr = std::make_unique<CryptoPP_HMAC_SHA_256_SymmetricKey>();

                            ptr->setValue(mySymmetricKey);

                            return ara::core::Result<SymmetricKey::Uptrc>(std::move(ptr));
                        }

                        else if(algId == HMAC_SHA_512_ALG_ID)
                        {
                            std::unique_ptr<CryptoPP_HMAC_SHA_512_SymmetricKey> ptr = std::make_unique<CryptoPP_HMAC_SHA_512_SymmetricKey>();

                            ptr->setValue(mySymmetricKey);

                            return ara::core::Result<SymmetricKey::Uptrc>(std::move(ptr));
                        }
                        else
                        {
                            return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                        }
                    }
                    else
                    {
                      return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleArguments, NoSupplementaryDataForErrorDescription));
                    }
                }
                else if(algId == RSA_2048_ALG_ID ||
                    algId == SHA_256_ALG_ID || algId == SHA_512_ALG_ID ||
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

            ara::core::Result<PrivateKey::Uptrc> CryptoPP_CryptoProvider::LoadPrivateKey (const IOInterface &container) noexcept
            {
                // check if IOInterface is valid or not
                if(!container.IsValid()) // return error
                    return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

              
                CryptoPP_IOInterface& cryptopp_IoInterface = dynamic_cast<CryptoPP_IOInterface&>(const_cast<IOInterface&>(container));
                std::string filePath = cryptopp_IoInterface.GetKeyMaterialPath();
                if(container.GetPrimitiveId() == RSA_2048_ALG_ID)
                {
                    
                
                    // check if file exists and is regular or not
                    if(!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
                        return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    // check if file is empty or not
                    std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
                    if(!fileStream.tellg())
                       return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kEmptyContainer, NoSupplementaryDataForErrorDescription));
                   
                    auto key = loadKey<CryptoPP::RSA::PrivateKey>(filePath);
                    std::unique_ptr<CryptoPP_RSA_2046_PrivateKey> ptr = std::make_unique<CryptoPP_RSA_2046_PrivateKey>();
                    ptr->setValue(key);
                    std::cout << "Loading Done" << std::endl;
                    
                    return  ara::core::Result<PrivateKey::Uptrc>::FromValue(std::move(ptr));
                }
                else if(container.GetPrimitiveId() == ECDSA_SHA_256_ALG_ID)
                {
                     // check if file exists and is regular or not
                    if(!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
                        return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    // check if file is empty or not
                    std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
                    if(!fileStream.tellg())
                       return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kEmptyContainer, NoSupplementaryDataForErrorDescription));
                    
                    auto key = loadKey<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(filePath);
                    std::unique_ptr<CryptoPP_ECDSA_PrivateKey> ptr = std::make_unique<CryptoPP_ECDSA_PrivateKey>();
                    ptr->setValue(key);
                    std::cout << "Loading Done" << std::endl;
                    
                    return  ara::core::Result<PrivateKey::Uptrc>::FromValue(std::move(ptr));
                }else{
                    return ara::core::Result<PrivateKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));

                }
             


            }
            ara::core::Result<SymmetricKey::Uptrc> CryptoPP_CryptoProvider::LoadSymmetricKey (const IOInterface &container) noexcept
            {
                 // check if IOInterface is valid or not
                if(!container.IsValid()) // return error
                    return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));
                
                CryptoPP_IOInterface& cryptopp_IoInterface = dynamic_cast<CryptoPP_IOInterface&>(const_cast<IOInterface&>(container));
                std::string filePath = cryptopp_IoInterface.GetKeyMaterialPath();

                if(container.GetPrimitiveId() == AES_ECB_128_ALG_ID || container.GetPrimitiveId() == AES_CBC_128_ALG_ID || 
                    container.GetPrimitiveId() == CHA_CHA_ALG_ID || container.GetPrimitiveId() == HMAC_SHA_256_ALG_ID || 
                    container.GetPrimitiveId() == HMAC_SHA_512_ALG_ID || container.GetPrimitiveId() == AUTH_CIPHER_ALG_ID || 
                    container.GetPrimitiveId() == RANDOM_GENERATOR_ALG_ID)
                {

                      // check if file exists and is regular or not
                    if(!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
                        return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    // check if file is empty or not
                    std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
                    if(!fileStream.tellg())
                       return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kEmptyContainer, NoSupplementaryDataForErrorDescription));
                    
                    auto key = loadSymmetricKey<CryptoPP::SecByteBlock>(filePath);
                    std::unique_ptr<CryptoPP_AES_128_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_128_SymmetricKey>();
                    ptr->setValue(key);
                    std::cout << "Loading Done" << std::endl;
                
                    return  ara::core::Result<SymmetricKey::Uptrc>::FromValue(std::move(ptr));
                }else{
                    return ara::core::Result<SymmetricKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));
 
                }
              
              
            }

            ara::core::Result<PublicKey::Uptrc> CryptoPP_CryptoProvider::LoadPublicKey (const IOInterface &container) noexcept
            {
                 // check if IOInterface is valid or not
                if(!container.IsValid()) // return error
                    return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

              
                CryptoPP_IOInterface& cryptopp_IoInterface = dynamic_cast<CryptoPP_IOInterface&>(const_cast<IOInterface&>(container));
                std::string filePath = cryptopp_IoInterface.GetKeyMaterialPath();
                if(container.GetPrimitiveId() == RSA_2048_ALG_ID)
                {
                    
                
                    // check if file exists and is regular or not
                    if(!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
                        return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    // check if file is empty or not
                    std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
                    if(!fileStream.tellg())
                       return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kEmptyContainer, NoSupplementaryDataForErrorDescription));
                   
                    auto key = loadKey<CryptoPP::RSA::PublicKey>(filePath);
                    std::unique_ptr<CryptoPP_RSA_2046_PublicKey> ptr = std::make_unique<CryptoPP_RSA_2046_PublicKey>();
                    ptr->setValue(key);
                    std::cout << "Loading Done" << std::endl;
                    
                    return  ara::core::Result<PublicKey::Uptrc>::FromValue(std::move(ptr));
                }
                else if(container.GetPrimitiveId() == ECDSA_SHA_256_ALG_ID)
                {
                     // check if file exists and is regular or not
                    if(!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
                        return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));

                    // check if file is empty or not
                    std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
                    if(!fileStream.tellg())
                       return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kEmptyContainer, NoSupplementaryDataForErrorDescription));
                    
                    auto key = loadKey<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(filePath);
                    std::unique_ptr<CryptoPP_ECDSA_SHA_256_PublicKey> ptr = std::make_unique<CryptoPP_ECDSA_SHA_256_PublicKey>();
                    ptr->setValue(key);
                    std::cout << "Loading Done" << std::endl;
                    
                    return  ara::core::Result<PublicKey::Uptrc>::FromValue(std::move(ptr));
                }else{
                    return ara::core::Result<PublicKey::Uptrc>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kIncompatibleObject, NoSupplementaryDataForErrorDescription));

                }
            }                                                         
            
        }
    }
}

