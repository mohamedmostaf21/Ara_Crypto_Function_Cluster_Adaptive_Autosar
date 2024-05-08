#ifndef DIGEST_SERVICE_H
#define DIGEST_SERVICE_H
#include <stdlib.h>
#include "../common/mem_region.h"
#include "block_service.h"
namespace ara{
    namespace crypto{
        namespace cryp{
            class DigestService : public BlockService 
            {
            public:
                using Uptr = std::unique_ptr<DigestService>;
                
                virtual ara::core::Result<bool> Compare ( ReadOnlyMemRegion expected, 
                                                        std::size_t offset=0
                                                        ) const noexcept=0;

                virtual std::size_t GetDigestSize () const noexcept=0;
                
                virtual bool IsFinished () const noexcept=0;
                
                virtual bool IsStarted () const noexcept=0;
            };
        }
    }
}
#endif /* DIGEST_SERVICE_H */
