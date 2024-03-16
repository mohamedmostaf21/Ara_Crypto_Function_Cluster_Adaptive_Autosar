#ifndef UUID_H
#define UUID_H

#include <cstdint>

namespace ara
{
    namespace crypto
    {
        /*
        UUID
            - refers to A Universally Unique Identifier 
            - is a 128-bit identifier that is standardized and used in software development to 
            uniquely identify information or entities.
        */
        struct Uuid
        {
            std::uint64_t mQwordLs = 0u;
            std::uint64_t mQwordMs = 0u;
            
            bool IsNil () const noexcept
            {
                return (mQwordLs == 0u && mQwordMs == 0u);
            }
        };

        constexpr bool operator== (const Uuid &lhs, const Uuid &rhs) noexcept
        {
            return (lhs.mQwordLs == rhs.mQwordLs) && (lhs.mQwordMs == rhs.mQwordMs);
        }

        constexpr bool operator<(const Uuid &lhs, const Uuid &rhs) noexcept
        {
            if (lhs.mQwordMs < rhs.mQwordMs)
                return true;
            else if (lhs.mQwordMs > rhs.mQwordMs)
                return false;
            else
                return lhs.mQwordLs < rhs.mQwordLs;
        }

        constexpr bool operator>(const Uuid &lhs, const Uuid &rhs) noexcept
        {
            return rhs < lhs;
        }

        constexpr bool operator!=(const Uuid &lhs, const Uuid &rhs) noexcept
        {
            return !(lhs == rhs);
        }

        constexpr bool operator<=(const Uuid &lhs, const Uuid &rhs) noexcept
        {
            return !(rhs < lhs);
        }

        constexpr bool operator>=(const Uuid &lhs, const Uuid &rhs) noexcept
        {
            return !(lhs < rhs);
        }
    }
}

#endif