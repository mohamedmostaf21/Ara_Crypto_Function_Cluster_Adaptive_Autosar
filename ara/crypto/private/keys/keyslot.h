#ifndef KEY_SLOT_H
#define KEY_SLOT_H
#include "../../../core/result.h"
#include "../../../core/vector.h"
#include "../../../core/utility.h"
#include "key_slot_content_props.h"
#include "key_slot_prototype_props.h"
#include "../common/io_interface.h"
namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class KeySlot
            {
            public:
                virtual ara::core::Result<void> Clear () noexcept=0;
                
                virtual ~KeySlot () noexcept=default;
                
                virtual ara::core::Result<KeySlotContentProps> GetContentProps () const noexcept=0;

                virtual ara::core::Result<cryp::CryptoProvider::Uptr> MyProvider () const noexcept=0;

                virtual ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept=0;

                virtual bool IsEmpty () const noexcept=0;
                
                virtual ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates=false, bool writeable=false) const noexcept=0;

                virtual ara::core::Result<void> SaveCopy (const IOInterface &container) noexcept=0;

                KeySlot& operator= (const KeySlot &other)=default;
                
                KeySlot& operator= (KeySlot &&other)=default;
                
                using Uptr = std::unique_ptr<KeySlot>;
            };
        }
    }
}
#endif /* KEY_SLOT_H */