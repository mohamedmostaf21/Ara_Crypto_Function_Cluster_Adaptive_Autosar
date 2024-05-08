#ifndef CRYPTOPP_CRYPTO_PRIMITIVE_ID_h
#define CRYPTOPP_CRYPTO_PRIMITIVE_ID_h

#include "../../../private/cryp/cryobj/crypto_primitive_id.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_CryptoPrimitiveId : public CryptoPrimitiveId
            {
            private:
                /*************** attributes ********************/
                AlgId mId;
                std::string mName;

            public:
                /**************** constructor ***********/
                CryptoPP_CryptoPrimitiveId(AlgId id, std::string name): mId(id), mName(name)
                {}

                /*********** override pure virtual functions inherited from parent ***********/
                AlgId GetPrimitiveId () const noexcept override
                {
                    return mId;
                }
                
                const ara::core::StringView GetPrimitiveName () const noexcept override
                {
                    return mName;
                }

                CryptoPP_CryptoPrimitiveId(const CryptoPP_CryptoPrimitiveId& obj)
                {
                    mId = obj.mId;
                    mName = obj.mName;
                }
            };
        }
    }
}

#endif