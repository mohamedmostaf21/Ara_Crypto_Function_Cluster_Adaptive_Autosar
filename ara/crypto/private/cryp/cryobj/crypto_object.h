#ifndef CRYPTO_OBJECT_H
#define CRYPTO_OBJECT_H

#include "../../common/base_id_types.h"
#include "../../common/crypto_object_uid.h"
#include "../../../../core/result.h"
#include "crypto_primitive_id.h"

#include <memory>



namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            /*
            A common interface for all cryptograhic objects recognizable by the Crypto Provider. This
            interface (or any its derivative) represents a non-mutable (after completion) object loadable to a
            temporary transformation context.
            */
            class CryptoObject 
            {
            public:
                struct COIdentifier 
                {
                    CryptoObjectType mCOType;
                    CryptoObjectUid mCouid;
                };
               

                using Uptr = std::unique_ptr<CryptoObject>;
                using Uptrc = std::unique_ptr<const CryptoObject>;

                
                /*
                Downcast and move unique smart pointer from the generic CryptoObject interface 
                to concrete derived object.
                */
                /*
                template <class ConcreteObject>
                static ara::core::Result<typename ConcreteObject::Uptrc> Downcast (CryptoObject::Uptrc &&object) noexcept
                {
                    auto derivedObject = dynamic_cast<typename ConcreteObject::Uptrc>(std::move(object));
                    if (derivedObject) 
                    {
                        Result<typename ConcreteObject::Uptrc> result{std::move(derivedObject)};
                        return result;
                    } 
                    else 
                    {
                        //return Result<typename ConcreteObject::Uptrc>::FromError(ErrorCode{"Downcast failed"});

                        ara::core::ErrorCode x =  ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kBadObjectType,5); 
                        return ara::core::Result<typename ConcreteObject::Uptrc>::FromError(x);
                    }
                }
                */

                /*
                
                virtual COIdentifier GetObjectId () const noexcept=0;

                virtual COIdentifier HasDependence () const noexcept=0;
           
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept=0;
                
                virtual std::size_t GetPayloadSize () const noexcept=0;
                
                virtual bool IsExportable () const noexcept=0;
                
                virtual bool IsSession () const noexcept=0;
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept=0;
                */


                /******************* default assigment operators *********************/
                CryptoObject& operator= (const CryptoObject &other)=default;

                CryptoObject& operator= (CryptoObject &&other)=default;
                


                /********** tell compiler to generate default deconstructor **********/
                virtual ~CryptoObject () noexcept=default;

            private:
                COIdentifier mCOIdentifier;
            };
        }
    }
}
#endif