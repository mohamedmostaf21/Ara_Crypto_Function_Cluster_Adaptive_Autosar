#ifndef SYMMETRIC_BLOCK_CIPHER_CTX_H
#define SYMMETRIC_BLOCK_CIPHER_CTX_H

#include "../../../core/result.h"
#include "../../../core/utility.h"
#include "crypto_context.h"
#include "cryobj/symmetric_key.h"
#include "../common/mem_region.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class SymmetricBlockCipherCtx : public CryptoContext 
            {
            public:
                using Uptr = std::unique_ptr<SymmetricBlockCipherCtx>;
                
                
                /********************** pure virtual functions *****************/
                /*
                    takes key and type of processing we want (type of operation ex:Encryption or decryption)
                */
                virtual ara::core::Result<void> SetKey ( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                    ) noexcept=0;
                
                
                virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;
                
                
                /* 
                    takes the data that we want to process (preform an operation on it)
                */
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlock ( ReadOnlyMemRegion in,
                                                                                            bool suppressPadding=false
                                                                                            ) const noexcept=0;

                
                
                //virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

                //virtual CryptoService::Uptr GetCryptoService () const noexcept=0;
                                                
                //virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}



#endif