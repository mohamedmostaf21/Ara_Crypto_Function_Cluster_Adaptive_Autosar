#ifndef EXTENSION_SERVICE_H_
#define EXTENSION_SERVICE_H_
#include "../common/base_id_types.h"
#include "../common/crypto_object_uid.h"
#include "cryobj/restricted_use_object.h"
namespace ara{
    namespace crypto{
        namespace cryp{
            class ExtensionService 
            {
            public:
                using Uptr = std::unique_ptr<ExtensionService>;
                
                
                
                virtual std::size_t GetActualKeyBitLength () const noexcept=0;

                virtual CryptoObjectUid GetActualKeyCOUID () const noexcept=0;

                virtual AllowedUsageFlags GetAllowedUsage () const noexcept=0;
                
                virtual std::size_t GetMaxKeyBitLength () const noexcept=0;

                virtual std::size_t GetMinKeyBitLength () const noexcept=0;

                virtual bool IsKeyBitLengthSupported (std::size_t keyBitLength) const noexcept=0;

                virtual bool IsKeyAvailable () const noexcept=0;
                
                
                
                ExtensionService& operator= (const ExtensionService &other)=default;

                ExtensionService& operator= (ExtensionService &&other)=default;
                
                virtual ~ExtensionService () noexcept=default;
            };

        }
    }
}

#endif /* EXTENSION_SERVICE_H_ */
