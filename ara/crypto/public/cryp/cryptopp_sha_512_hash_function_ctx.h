#ifndef CRYPTOPP_SHA_512_HASH_FUNCTION_CTX_H
#define CRYPTOPP_SHA_512_HASH_FUNCTION_CTX_H

#include "../../private/cryp/hash_function_ctx.h"
#include "cryobj/cryptopp_crypto_primitive_id.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include "../../helper/state.h"
#include <iostream>
#include <sstream>
#include <iomanip>


namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            /*
                this helper class doesnot be mentioned in autosar 
            */

            using namespace helper;
            class CryptoPP_SHA_512_HashFunctionCtx: public HashFunctionCtx 
            {
            public :
                /******************* constants **********************/
                static const std::string mAlgName;
                const CryptoPrimitiveId::AlgId mAlgId = 2;
            
            private:
                /***************************** attributes *******************/
                CryptoPP::SHA512 hash;
                CryptoPP::SecByteBlock digest;   
                CryptoPP_CryptoPrimitiveId mPId;
                helper::calling seq;

            public:  
                /********************** constructor **************************/
                
                CryptoPP_SHA_512_HashFunctionCtx();


                /****** override pure virtual functions related to CryptoContext *****/

                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override;

                virtual bool IsInitialized () const noexcept override;


                /***** override pure virtual functions inherited related HashFunctionCtx *****/

                virtual ara::core::Result<void> Start () noexcept override;

                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv) noexcept override;

                ara::core::Result<void> Update (std::uint8_t in) noexcept override;

                ara::core::Result<void> Update (ReadOnlyMemRegion in) noexcept override;

                ara::core::Result<ara::core::Vector<ara::core::Byte> > Finish() noexcept override;
                
                ara::core::Result<ara::core::Vector<ara::core::Byte> > GetDigest(std::size_t offset=0) noexcept override;
            

            };
        }
    }
}

#endif