#ifndef _ELEMENTRY_TYPES_H_
#define _ELEMENTRY_TYPES_H_
#include"KeySlot.h"
#include"../../core/vector.h"


namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            using TransactionId = std::uint64_t;
            using TransactionScope = ara::core::Vector<KeySlot>;

        }
    }

}

#endif 
