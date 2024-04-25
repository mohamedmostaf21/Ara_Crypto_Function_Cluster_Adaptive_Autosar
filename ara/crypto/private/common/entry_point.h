#ifndef ENTRY_POINT_H
#define ENTRY_POINT_H

#include <cstdint>
#include "../../../core/result.h"
#include "../../../core/instance_specifier.h"
#include "../../public/cryp/cryptopp_crypto_provider.h"

namespace ara
{
    namespace crypto
    {
        struct SecureCounter 
        {
            std::uint64_t mLSQW;
            std::uint64_t mMSQW;
        };

        
        cryp::CryptoProvider::Uptr LoadCryptoProvider (const ara::core::InstanceSpecifier &iSpecify) noexcept
        {
           if(iSpecify.ToString() == "cryptopp")
           {
                std::cout << iSpecify.ToString() << std::endl;
                
                return std::make_unique<cryp::CryptoPP_CryptoProvider>();
           }
           else
           {
                std::cout << "not provider\n";
                return nullptr;
           }
        }
        
        //keys::KeyStorageProvider::Uptr LoadKeyStorageProvider () noexcept;

        //x509::X509Provider::Uptr LoadX509Provider () noexcept;

        ara::core::Result<ara::core::Vector<ara::core::Byte>> GenerateRandomData (std::uint32_t count) noexcept;

        ara::core::Result<SecureCounter> GetSecureCounter () noexcept;
    }
}

#endif