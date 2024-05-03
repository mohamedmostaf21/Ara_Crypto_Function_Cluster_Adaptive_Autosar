#ifndef _KEY_SLOT_H_
#define _KEYSLOT_H_
#include <string>
#include"../../core/instance_specifier.h"
#include"../../core/vector.h"
#include "../private/cryp/cryobj/symmetric_key.h"
#include "../private/cryp/cryobj/private_key.h"
#include "../private/cryp/cryobj/public_key.h"
#include "cryptopp_io_interface.h"
#include"../public/cryp/cryobj/cryptopp_aes_128_symmetric_key.h"
#include"../public/cryp/cryobj/cryptopp_ecdsa_sha_256_private_key.h"
#include"../public/cryp/cryobj/cryptopp_ecdsa_sha_256_public_key.h"
#include"../public/cryp/cryobj/cryptopp_rsa_2046_private_key.h"
#include"../public/cryp/cryobj/cryptopp_rsa_2046_public_key.h"
#include "../private/common/io_interface.h"
#include "key_slot_prototype_props.h"
using namespace std;


namespace ara
{
    namespace crypto
    {

        namespace keys
        {
            using namespace cryp;
            class KeySlot 
            {
                
            public:
                using Uptr = std::unique_ptr<KeySlot>;
                
                void setmeta(std::string  InstanceSpecifier,std::string  CryptoProvider,std::string  KeyMaterialPath, CryptoAlgId  AlgId, crypto::AllowedUsageFlags  AllowedUsageFlags, crypto::CryptoObjectType   CryptoObjectType,bool  Exportable,KeySlotType  SlotType,std::size_t  SlotCapacity,bool  AllocateShadowCopy,bool  AllowContentTypeChange,int32_t  MaxUpdateAllowed);
                void KeySlotContentProps() const noexcept;
                ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept;
                bool IsEmpty() const noexcept;
                ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates=false, bool writeable=false) const;
                KeySlotType GetSlotType(std::string slotType);
                //KeySlot &operator=(const KeySlot &other) = default;
                CryptoObjectType GetObjectType(std::string object);
                std::string ToString(const crypto::CryptoObjectType& cryptoObject) const;
                std::string ToString(const crypto::KeySlotType& slotType) const;
                std::string boolToString(bool flag) const noexcept;
                bool IsModified() const noexcept;
                //KeySlot &operator=(KeySlot &&other) = default;
            private:
           
                //meta data
                std::string  InstanceSpecifier;
                std::string  CryptoProvider;
                std::string  KeyMaterialPath;
                CryptoAlgId  AlgId;
                crypto::AllowedUsageFlags AllowedUsageFlags;
                crypto::CryptoObjectType  Crypto_Object_Type;
                bool  Exportable;
                KeySlotType  SlotType;
                std::size_t  SlotCapacity;
                bool  AllocateShadowCopy;
                bool AllowContentTypeChange;
                int32_t  MaxUpdateAllowed;
                bool isempty;    
                bool modified;
                bool reserveSpareSlot;
   
            
            };
        }
    }
}

#endif 