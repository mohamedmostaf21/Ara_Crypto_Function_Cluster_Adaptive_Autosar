#include "cryptopp_sha_256_hash_function_ctx.h"
#include "../../private/common/crypto_error_domain.h"
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {    
            extern CryptoErrorDomain _obj;

            const std::string CryptoPP_SHA_256_HashFunctionCtx::mAlgName("sha_256");

            /********************** constructor **************************/
            CryptoPP_SHA_256_HashFunctionCtx::CryptoPP_SHA_256_HashFunctionCtx(): HashFunctionCtx(),
                                                                                  mPId(mAlgId,mAlgName),
                                                                                  seq{calling::START_IS_NOT_CALLED}
            {
                
            }


            /****** override pure virtual functions related to CryptoContext *****/

            CryptoPrimitiveId::Uptr CryptoPP_SHA_256_HashFunctionCtx::GetCryptoPrimitiveId () const noexcept
            {
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
            
            bool CryptoPP_SHA_256_HashFunctionCtx::IsInitialized () const noexcept
            {
                return true;
            }

            
            /***** override pure virtual functions inherited related HashFunctionCtx *****/
            
            ara::core::Result<void> CryptoPP_SHA_256_HashFunctionCtx::Start (ReadOnlyMemRegion iv) noexcept
            {
                ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kUnsupported,5); 
                return ara::core::Result<void>::FromError(x);
            }

            ara::core::Result<void> CryptoPP_SHA_256_HashFunctionCtx::Start () noexcept
            {
                seq = calling::START_IS_CALLED;
                
                hash.Restart();
                return ara::core::Result<void>::FromValue();
            }
            
            ara::core::Result<void> CryptoPP_SHA_256_HashFunctionCtx::Update (ReadOnlyMemRegion in) noexcept
            {  
                if(seq == calling::START_IS_NOT_CALLED)
                {
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,5); 
                    return ara::core::Result<void>::FromError(x);
                }

                seq = calling::UPDATE_IS_CALLED;
                
                hash.Update(in.data(), in.size());
                return ara::core::Result<void>::FromValue();
            }

            ara::core::Result<void> CryptoPP_SHA_256_HashFunctionCtx::Update (std::uint8_t in) noexcept
            {
                if(seq == calling::START_IS_NOT_CALLED)
                {
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,5); 
                    return ara::core::Result<void>::FromError(x);
                }

                seq = calling::UPDATE_IS_CALLED;
                
                hash.Update((const CryptoPP::byte*)&in, sizeof(in));
                return ara::core::Result<void>::FromValue();
            }

            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_SHA_256_HashFunctionCtx::Finish() noexcept
            {
                if(seq == calling::START_IS_NOT_CALLED)
                {
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,5); 
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(x);
                }
                else if(seq == calling::UPDATE_IS_CALLED)
                {
                    seq = calling::FINISH_IS_CALLED;

                    digest.resize(hash.DigestSize());
                    hash.Final(digest);

                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : digest)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }

                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
                }
                else if(seq == calling::FINISH_IS_CALLED)
                {
                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : digest)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }

                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
                }
                else
                {
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kInvalidUsageOrder,5); 
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(x);
                }
            }

            ara::core::Result<ara::core::Vector<ara::core::Byte>> CryptoPP_SHA_256_HashFunctionCtx::GetDigest (std::size_t offset) noexcept
            {
                if(seq == calling::FINISH_IS_CALLED)
                {
                    ara::core::Vector<ara::core::Byte> result;
                    for (const auto& byte : digest)
                    {
                        result.push_back(static_cast<ara::core::Byte>(byte));
                    }

                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromValue(result);
                }
                else
                {
                    ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kProcessingNotStarted,5); 
                    return ara::core::Result<ara::core::Vector<ara::core::Byte>>::FromError(x);
                }
            }
            

            
            /*********** not fundemental and overrided functions **************/

            //virtual ara::core::Result<void> Start (const SecretSeed &iv) noexcept;

            // ara::core::Result<void> Update (const RestrictedUseObject &in) noexcept;        
        }
    }
}
