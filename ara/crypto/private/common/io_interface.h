#ifndef IO_INTERFACE_H
#define IO_INTERFACE_H
#include "crypto_object_uid.h"
//#include "../cryp/cryobj/crypto_object.h"
#include "../../private/keys/key_slot_prototype_props.h"
namespace ara
{
    namespace crypto
    {

        class IOInterface
        {
        public:
            using Uptr = std::unique_ptr<IOInterface>;
            using Uptrc = std::unique_ptr<const IOInterface>;

           
            
            virtual AllowedUsageFlags GetAllowedUsage () const noexcept=0;
            
            virtual std::size_t GetCapacity () const noexcept=0;
            
            virtual CryptoObjectType GetCryptoObjectType () const noexcept=0;
            
           // virtual CryptoObjectUid GetObjectId () const noexcept=0;
            
            virtual std::size_t GetPayloadSize () const noexcept=0;
            
            virtual CryptoAlgId GetPrimitiveId () const noexcept=0;
            
            //virtual CryptoObjectType GetTypeRestriction () const noexcept=0;
           
            virtual bool IsObjectExportable () const noexcept=0;
            
            // virtual bool IsObjectSession () const noexcept=0;
            
            // virtual bool IsVolatile () const noexcept=0;
            
            virtual bool IsValid () const noexcept=0;
            
            virtual bool IsWritable () const noexcept=0;
          
            
            template <typename T>
            T FromValue(T &&t)
            {
                T _result{std::move(t)};
                return _result;
            }
            IOInterface& operator= (const IOInterface &other)=default;
            
            IOInterface& operator= (IOInterface &&other)=default;
            
            virtual ~IOInterface () noexcept=default;
        };
    }
}

#endif /* IO_INTERFACE_H */
