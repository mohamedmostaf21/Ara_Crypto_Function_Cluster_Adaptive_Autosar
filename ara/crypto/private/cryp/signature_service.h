#ifndef SIGNATURE_SERVICE_H_
#define SIGNATURE_SERVICE_H_
#include "cryobj/crypto_primitive_id.h"
#include "extension_service.h"
namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class SignatureService : public ExtensionService 
            {
            public:
                using Uptr = std::unique_ptr<SignatureService>;
                
                
                
                virtual CryptoPrimitiveId::AlgId GetRequiredHashAlgId () const noexcept=0;

                virtual std::size_t GetRequiredHashSize () const noexcept=0;

                virtual std::size_t GetSignatureSize () const noexcept=0;
            };
        }
    }
}
#endif /* SIGNATURE_SERVICE_H_ */
