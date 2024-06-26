#ifndef STREAM_CIPHER_CTX_H
#define STREAM_CIPHER_CTX_H

#include "../../../core/utility.h"
#include "../common/mem_region.h"
#include "crypto_context.h"
#include "cryobj/symmetric_key.h"

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class StreamCipherCtx : public CryptoContext 
            {
            public:
                using Uptr = std::unique_ptr<StreamCipherCtx>;


                //Count number of bytes now kept in the context cache. 
                //virtual std::size_t CountBytesInCache () const noexcept=0;

                //Check the operation mode for the bytewise property
                //virtual bool IsBytewiseMode () const noexcept=0;

                //Check if the seek operation is supported in the current mode
                //virtual bool IsSeekableMode () const noexcept=0;


                //virtual ara::core::Result<void> Seek (std::int64_t offset, bool fromBegin=true) noexcept=0;


                virtual ara::core::Result<void> Start (ReadOnlyMemRegion iv=ReadOnlyMemRegion()) noexcept=0;
                
                
                /********************** pure virtual functions *****************/
                // takes key and type of processing we want (type of operation ex:Encryption or decryption)
                virtual ara::core::Result<void> SetKey ( const SymmetricKey &key,
                                                        CryptoTransform transform=CryptoTransform::kEncrypt
                                                    ) noexcept=0;
                
                
                virtual ara::core::Result<CryptoTransform> GetTransformation () const noexcept=0;
                
                
                //  takes the data that we want to process (preform an operation on it)
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks
                 (ReadOnlyMemRegion in) noexcept=0;


                 //takes the data that we want to process (preform an operation on it)
                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBytes
                 (ReadOnlyMemRegion in) noexcept=0;


                virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > FinishBytes
                 (ReadOnlyMemRegion in) noexcept=0;

                
                
                //virtual ara::core::Result<ara::core::Vector<ara::core::Byte> > ProcessBlocks (ReadOnlyMemRegion in) const noexcept=0;

                //virtual CryptoService::Uptr GetCryptoService () const noexcept=0;
                                                
                //virtual ara::core::Result<void> Reset () noexcept=0;
            };
        }
    }
}



#endif