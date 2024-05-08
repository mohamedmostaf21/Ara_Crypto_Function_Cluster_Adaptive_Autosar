#ifndef VOLATILE_TRUSTED_CONTAINER_H_
#define VOLATILE_TRUSTED_CONTAINER_H_
#include "stdlib.h"
#include "io_interface.h"

namespace ara {
    namespace crypto{
        class VolatileTrustedContainer
        {
        public:
            using Uptr = std::unique_ptr<VolatileTrustedContainer>;
            
            virtual IOInterface& GetIOInterface () const noexcept=0;
            
            
            
            VolatileTrustedContainer& operator= (const VolatileTrustedContainer &other)=default;

            VolatileTrustedContainer& operator= (VolatileTrustedContainer &&other)=default;
            
            virtual ~VolatileTrustedContainer () noexcept=default;
        };

    }
}

#endif /* VOLATILE_TRUSTED_CONTAINER_H_ */
