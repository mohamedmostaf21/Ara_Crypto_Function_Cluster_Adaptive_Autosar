#ifndef KEY_SLOT_PROTOTYPE_PROPS_H
#define KEY_SLOT_PROTOTYPE_PROPS_H

#include<memory>
#include "../common/base_id_types.h"
#include "../common/crypto_object_uid.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            /*
                "InstanceSpecifier"  : "rsa_2046_public_key_1",
                "CryptoProvider"     : "CryptoppCryptoProvider",
                "KeyMaterialPath"    : "rsa_2046_public_key_1.key",
                
                -y-> "ALgId"              : 5,
                -y-> "AllowUsageFlags"    : 4,
                -y-> "CryptoObjectType"   : "kPublicKey",
                -y-> "Exportable"         : true,
                -y-> "SlotType"           : "kApplication",
                -y-> "slotCapacity"       : 10000,
                -y-> "AllocateShadowCopy" : false,
                -y-> "MaxUpdateAllowed"   : -1
            */
            struct KeySlotPrototypeProps
            {
                using Uptr = std::unique_ptr<KeySlotPrototypeProps>;
                
                CryptoAlgId mAlgId;
                AllowedUsageFlags mContentAllowedUsage;
                CryptoObjectType mObjectType;
                bool mExportAllowed;
                KeySlotType mSlotType;
                std::size_t mSlotCapacity;
                bool mAllocateSpareSlot;
                bool mAllowContentTypeChange;
                std::int32_t mMaxUpdateAllowed;

                KeySlotPrototypeProps ()=default;
            };

            constexpr bool operator== (const KeySlotPrototypeProps &lhs, const KeySlotPrototypeProps &rhs) noexcept;

            constexpr bool operator!= (const KeySlotPrototypeProps &lhs, const KeySlotPrototypeProps &rhs) noexcept;
        }
    }
}

#endif