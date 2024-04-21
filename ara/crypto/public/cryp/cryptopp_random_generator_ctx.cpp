#include "cryptopp_random_generator_ctx.h"
#include <cryptopp/cryptlib.h>
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
       
            const std::string Cryptopp_RandomGeneratorctx::mAlgName("random_generator");
            Cryptopp_RandomGeneratorctx::Cryptopp_RandomGeneratorctx () : RandomGeneratorCtx(),
                                                                        mKey(nullptr),
                                                                        mPId(mAlgId,mAlgName),
                                                                        rng(new CryptoPP::AutoSeededRandomPool()),
                                                                        mSetKeyState(helper::setKeyState::NOT_CALLED)
            {
                   
            }
            
            /****** override pure virtual functions related to CryptoContext *****/

            CryptoPrimitiveId::Uptr Cryptopp_RandomGeneratorctx::GetCryptoPrimitiveId () const noexcept
            {
                return std::make_unique<CryptoPP_CryptoPrimitiveId>(mPId);
            }
            
            bool Cryptopp_RandomGeneratorctx::IsInitialized () const noexcept
            {
                return (mSetKeyState == helper::setKeyState::CALLED && mKey != nullptr);
            }

            ara::core::Result< ara::core::Vector<ara::core::Byte> > Cryptopp_RandomGeneratorctx::Generate (std::uint32_t count) noexcept
            {
                ara::core::Vector<CryptoPP::byte> cipher;
                CryptoPP::SecByteBlock scratch(count);

                rng.GenerateBlock(scratch, scratch.size());
                for(int i = 0; i < scratch.size(); i++)
                {
                    cipher.push_back(scratch[i]);
                }
                return cipher;
            }

            // ExtensionService::Uptr Cryptopp_RandomGeneratorctx::GetExtensionService ()  const noexcept
            // {
            //       return std::make_unique<ExtensionService>();
            // }


            bool  Cryptopp_RandomGeneratorctx::AddEntropy (ReadOnlyMemRegion entropy) noexcept
            {
                if(rng.CanIncorporateEntropy())
                {
                    rng.IncorporateEntropy((const CryptoPP::byte*)entropy.data(), entropy.size());
                    return true;
                }
                else
                {
                    return false;
                }
                
            }
            
            bool Cryptopp_RandomGeneratorctx::Seed (ReadOnlyMemRegion seed) noexcept
            {
                rng.Reseed(false,seed.size());
                return true;
            }

            // bool Cryptopp_RandomGeneratorctx::Seed (const SecretSeed &seed) noexcept
            // {
            //     rng.Reseed(false,);
            // }
            
            bool Cryptopp_RandomGeneratorctx::SetKey (const SymmetricKey &key) noexcept
            {  
                const CryptoPP_AES_SymmetricKey& aesKey = dynamic_cast<const CryptoPP_AES_SymmetricKey&>(key);
                //if(aesKey.GetAllowedUsage() == kAllowRngInit)
                if(aesKey.GetAllowedUsage())
                {
                    mKey = new CryptoPP_AES_SymmetricKey(aesKey);
                    
                    mSetKeyState = helper::setKeyState::CALLED;
                    return true;
                }
                else 
                {
                    std::cerr << "Failed to cast SymmetricKey to CryptoPP_AES_SymmetricKey: " << std::endl;
                    return false;
                }
             
            }

            Cryptopp_RandomGeneratorctx::~Cryptopp_RandomGeneratorctx ()
            {
            
            }

        }
    }
}
