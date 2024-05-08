#ifndef BLOCK_SERVICE_H
#define BLOCK_SERVICE_H
#include "extension_service.h"

namespace ara{
    namespace crypto{
        namespace cryp{
            class BlockService : public ExtensionService 
            {
            public:
                using Uptr = std::unique_ptr<BlockService>;
                
                
                
                virtual std::size_t GetActualIvBitLength (ara::core::Optional< CryptoObjectUid > ivUid) const noexcept=0;

                virtual std::size_t GetBlockSize () const noexcept=0;
                
                virtual std::size_t GetIvSize () const noexcept=0;
                
                virtual bool IsValidIvSize (std::size_t ivSize) const noexcept=0;
            };
        }
    }
}
#endif /* BLOCK_SERVICE_H */
