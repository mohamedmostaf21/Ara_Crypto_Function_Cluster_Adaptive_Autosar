#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include "cryobj/crypto_primitive_id.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoContext 
            {
            public:
                using AlgId = CryptoAlgId;
                
                /*************** pure virtual functions ***********/
                //virtual CryptoProvider& MyProvider () const noexcept=0;

                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept=0;

                virtual bool IsInitialized () const noexcept=0;



                /*********** copy assignment operators *******/
                CryptoContext& operator= (const CryptoContext &other)=default;

                /*********** move assignment operators *******/
                CryptoContext& operator= (CryptoContext &&other)=default;
                
                /************* deconstructor ***********/
                virtual ~CryptoContext () noexcept=default;
            };
        }
    }
}

#endif