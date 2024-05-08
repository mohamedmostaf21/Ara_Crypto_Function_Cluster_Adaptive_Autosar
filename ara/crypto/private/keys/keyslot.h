#ifndef KEY_SLOT_H
#define KEY_SLOT_H

#include "../../../core/result.h"
#include "../common/io_interface.h"
#include "key_slot_content_props.h"
#include "key_slot_prototype_props.h"
#include "../common/crypto_error_domain.h"
namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class KeySlot
            {
            public:
                using Uptr = std::unique_ptr<KeySlot>;

                virtual ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates=false, bool writeable=false) const noexcept=0;

                //virtual ara::core::Result<KeySlotContentProps> GetContentProps () const noexcept=0;

                virtual ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept=0;

                /*
                virtual ara::core::Result<cryp::CryptoProvider::Uptr> MyProvider () const noexcept=0;
        
                virtual ara::core::Result<void> Clear () noexcept=0;

             

                virtual ara::core::Result<void> SaveCopy (const IOInterface &container) noexcept=0;
                */

                virtual  void setmeta(std::string  InstanceSpecifier,std::string  CryptoProvider,std::string  KeyMaterialPath, CryptoAlgId  AlgId, crypto::AllowedUsageFlags  AllowedUsageFlags, crypto::CryptoObjectType   CryptoObjectType,bool  Exportable,KeySlotType  SlotType,std::size_t  SlotCapacity,bool  AllocateShadowCopy,bool  AllowContentTypeChange,int32_t  MaxUpdateAllowed)=0;
                virtual KeySlotType GetSlotType(std::string slotType)=0;
                virtual  void printData() const noexcept=0;
                virtual   CryptoObjectType GetObjectType(std::string object)=0;
                virtual bool IsEmpty () const noexcept=0;
                KeySlot& operator= (const KeySlot &other)=default;
                
                KeySlot& operator= (KeySlot &&other)=default;
                
                virtual ~KeySlot () noexcept=default;
            };
        }   
    }   
}

#endif