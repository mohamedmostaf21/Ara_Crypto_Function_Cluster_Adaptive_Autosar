#ifndef CRYPTOPP_CRYPTO_PRIMITIVE_ID_h
#define CRYPTOPP_CRYPTO_PRIMITIVE_ID_h


#include "../../../private/cryp/cryobj/crypto_primitive_id.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            /*
            class CryptoPrimitiveId 
            {
            public:
                using Uptrc = std::unique_ptr<const CryptoPrimitiveId>;
                using Uptr = std::unique_ptr<CryptoPrimitiveId>;
                using AlgId = CryptoAlgId;


                virtual AlgId GetPrimitiveId () const noexcept=0;
                
                virtual const ara::core::StringView GetPrimitiveName () const noexcept=0;


                CryptoPrimitiveId& operator= (const CryptoPrimitiveId &other)=default;

                CryptoPrimitiveId& operator= (CryptoPrimitiveId &&other)=default;
                    
                virtual ~CryptoPrimitiveId () noexcept=default;
            };
            */

            class CryptoPP_CryptoPrimitiveId : public CryptoPrimitiveId
            {
                /*************** attributes ********************/
            private:
                AlgId mId;
                std::string mName;

            public:
                /**************** constructor ***********/
                CryptoPP_CryptoPrimitiveId(AlgId id, std::string name): mId(id), mName(name)
                {

                }

                /*********** override pure virtual functions inherited from parent ***********/
                virtual AlgId GetPrimitiveId () const noexcept override
                {
                    return mId;
                }
                
                virtual const ara::core::StringView GetPrimitiveName () const noexcept override
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