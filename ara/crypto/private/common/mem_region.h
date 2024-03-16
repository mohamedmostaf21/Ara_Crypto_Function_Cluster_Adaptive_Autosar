#ifndef MEM_REGION_H
#define MEM_REGION_H

#include <cstdint>
#include "../../../core/Span.h"
#include "cryptopp/config.h" // Include Crypto++ config header
#include "cryptopp/osrng.h" // Include Crypto++ OS Random Number Generator header

namespace ara
{
    namespace crypto
    {
        // Define a struct to hold seed data along with its length
        struct SeedData {
            const CryptoPP::byte* seed;
            std::size_t length;
        };
        using ReadOnlyMemRegion = ara::core::Span<const std::uint8_t>;
        using ReadWriteMemRegion = ara::core::Span<std::uint8_t>;
      
    }
}


#endif