#ifndef KEY_SLOT_CONTENT_PROPS_H
#define KEY_SLOT_CONTENT_PROPS_H

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
                --> "Exportable"         : true,
                --> "SlotType"           : "kApplication",
                --> "slotCapacity"       : 10000,
                --> "AllocateShadowCopy" : false,
                --> "MaxUpdateAllowed"   : -1
            */

            struct KeySlotContentProps
            {
                using Uptr = std::unique_ptr<KeySlotContentProps>;

                CryptoAlgId mAlgId;
                AllowedUsageFlags mContentAllowedUsage;
                CryptoObjectType mObjectType;
                
                std::size_t mObjectSize;
                CryptoObjectUid mObjectUid;

                KeySlotContentProps ()=default;
            };

            constexpr bool operator== (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;

            constexpr bool operator!= (const KeySlotContentProps &lhs, const KeySlotContentProps &rhs) noexcept;           
        }
    }
}


#endif