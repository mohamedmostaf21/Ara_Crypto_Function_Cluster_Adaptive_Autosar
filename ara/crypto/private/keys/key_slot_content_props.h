#ifndef KEY_SLOT_CONTENT_PROPS_H
#define KEY_SLOT_CONTENT_PROPS_H
#include "../cryp/cryobj/crypto_primitive_id.h"
#include "../common/crypto_object_uid.h"
namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            constexpr bool operator== (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;

            constexpr bool operator!= (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;

            struct KeySlotContentProps
            {
                using Uptr = std::unique_ptr<KeySlotContentProps>;

                KeySlotContentProps ()=default;
                
                crypto::CryptoAlgId mAlgId;
                
                std::size_t mObjectSize;
                
                CryptoObjectType mObjectType;
                
                CryptoObjectUid mObjectUid;
                
                AllowedUsageFlags mContentAllowedUsage;
            };
        }
    }
}
#endif /* KEY_SLOT_CONTENT_PROPS_H */
