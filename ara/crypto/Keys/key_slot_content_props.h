#ifndef KEY_SLOT_CONTENT_PROPS
#define KEY_SLOT_CONTENT_PROPS

#include "stdlib.h"
#include "../private/cryp/cryobj/crypto_object.h"
namespace ara
{
    namespace crypto
    {

        namespace keys
        {   
           // constexpr bool operator== (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;

            //constexpr bool operator!= (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;

            struct KeySlotContentProps
            {
                using Uptr = std::unique_ptr<KeySlotContentProps>;

                KeySlotContentProps ()=default;
                
                CryptoAlgId mAlgId;
                
                std::size_t mObjectSize;
                
                CryptoObjectType mObjectType;
                
                CryptoObjectUid mObjectUid;
                
                AllowedUsageFlags mContentAllowedUsage;
            };

        }
    }
}

#endif /* KEY_SLOT_CONTENT_PROPS */
