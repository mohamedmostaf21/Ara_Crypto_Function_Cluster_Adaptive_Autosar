#ifndef CRYPTO_OBJECT_UID_H
#define CRYPTO_OBJECT_UID_H

#include "uuid.h"

namespace ara
{
    namespace crypto
    {
        struct CryptoObjectUid
        {
            Uuid mGeneratorUid;

            /*
            Sequential value of a steady timer or simple counter,
            representing version of correspondent Crypto Object
            */
            std::uint64_t mVersionStamp = 0u; 
            

            constexpr bool HasEarlierVersionThan(const CryptoObjectUid &anotherId) const noexcept
            {
                return mVersionStamp < anotherId.mVersionStamp;
            }

            constexpr bool HasLaterVersionThan(const CryptoObjectUid &anotherId) const noexcept
            {
                return mVersionStamp > anotherId.mVersionStamp;
            }

            constexpr bool HasSameSourceAs(const CryptoObjectUid &anotherId) const noexcept
            {
                return mGeneratorUid.mQwordLs == anotherId.mGeneratorUid.mQwordLs &&
                    mGeneratorUid.mQwordMs == anotherId.mGeneratorUid.mQwordMs;
            }

            bool IsNil() const noexcept
            {
                return mGeneratorUid.IsNil() && mVersionStamp == 0u;
            }

            bool SourceIsNil() const noexcept
            {
                return mGeneratorUid.IsNil();
            }
        };

        /*
        true if all members’ values of lhs is equal to rhs
        false otherwise
        */
        constexpr bool operator== (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return lhs.mGeneratorUid.mQwordLs == rhs.mGeneratorUid.mQwordLs &&
                   lhs.mGeneratorUid.mQwordMs == rhs.mGeneratorUid.mQwordMs &&
                   lhs.mVersionStamp == rhs.mVersionStamp;
        }

        /* 
        true if a binary representation of lhs is less than rhs
        false otherwise*/
        constexpr bool operator< (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return lhs.mGeneratorUid < rhs.mGeneratorUid;
        }

        /*
        true if a binary representation of lhs is greater than rhs
        false otherwise
        */
        constexpr bool operator> (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return lhs.mGeneratorUid > rhs.mGeneratorUid;
        }

        /*
        true if at least one member of lhs has a value not equal to correspondent member of rhs
        false otherwise
        */
        constexpr bool operator!= (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return !(lhs == rhs);
        }

        /*
        true if a binary representation of lhs is less than or equal to rhs
        false otherwise
        */
        constexpr bool operator<= (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return !(rhs < lhs);
        }

        /*
        true if a binary representation of lhs is greater than or equal to rhs
        false otherwise
        */
        constexpr bool operator>= (const CryptoObjectUid &lhs, const CryptoObjectUid &rhs) noexcept
        {
            return !(lhs < rhs);
        }
    }
}


#endif