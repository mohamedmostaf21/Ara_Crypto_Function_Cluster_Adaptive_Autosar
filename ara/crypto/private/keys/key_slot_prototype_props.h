#ifndef KEY_SLOT_PROTOTYPE_PROPS_H
#define KEY_SLOT_PROTOTYPE_PROPS_H
#include "../cryp/cryobj/crypto_primitive_id.h"
namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            constexpr bool operator== (const KeySlotPrototypeProps &lhs, const KeySlotPrototypeProps &rhs) noexcept;

            constexpr bool operator!= (const KeySlotPrototypeProps &lhs, const KeySlotPrototypeProps &rhs) noexcept;

            struct KeySlotPrototypeProps
            {
                using Uptr = std::unique_ptr<KeySlotPrototypeProps>;
                
                KeySlotPrototypeProps ()=default;
                
                CryptoAlgId mAlgId;
                
                bool mAllocateSpareSlot;
                
                bool mAllowContentTypeChange;
                
                AllowedUsageFlags mContentAllowedUsage;
                
                bool mExportAllowed;
                
                std::int32_t mMaxUpdateAllowed;
                
                KeySlotType mSlotType;
                
                std::size_t mSlotCapacity;
                
                CryptoObjectType mObjectType;
            };
        }
    }
}
#endif /* KEY_SLOT_PROTOTYPE_PROPS_H */
