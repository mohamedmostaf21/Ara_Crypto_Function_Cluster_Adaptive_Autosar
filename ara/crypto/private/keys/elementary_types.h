#ifndef ELEMENTARY_TYPES_H
#define ELEMENTARY_TYPES_H

#include "keyslot.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            using TransactionId = std::uint64_t;
            using TransactionScope = ara::core::Vector<KeySlot::Uptr>;
        }
    }
}




#endif