#ifndef CRYPTOPP_IO_INTERFACE_H_
#define CRYPTOPP_IO_INTERFACE_H_
#include "../private/common/io_interface.h"
#include "../public/cryp/cryobj/cryptopp_crypto_primitive_id.h"

namespace ara
{
    namespace crypto 
    {
       
        class CryptoPP_IOInterface : public IOInterface
        {
            private:
            CryptoAlgId mAlgId;
            
            AllowedUsageFlags mContentAllowedUsage;
            std::string KeyMaterialPath;
            bool mExportAllowed;
            
            std::size_t mSlotCapacity;
            
            CryptoObjectType mObjectType;
            public:


            void setInterface( AllowedUsageFlags mContentAllowedUsage,  std::size_t mSlotCapacity,  CryptoObjectType mObjectType,  CryptoAlgId mAlgId,  bool mExportAllowed, std::string KeyMaterialPath) override
            {
                this->mContentAllowedUsage = mContentAllowedUsage;
                this->mSlotCapacity = mSlotCapacity;
                this->mObjectType = mObjectType;
                this->mAlgId = mAlgId;
                this->mExportAllowed = mExportAllowed;
                this->KeyMaterialPath = KeyMaterialPath;
            }
            /************* override parent functions ************/
           
            AllowedUsageFlags GetAllowedUsage () const noexcept override
            {
                return  this->mContentAllowedUsage;
            }

            std::size_t GetCapacity () const noexcept override
            {
                return  this->mSlotCapacity;
            }
            std::size_t GetPayloadSize () const noexcept override
            {
                return 16;
            }

            CryptoObjectType GetCryptoObjectType () const noexcept override
            {
                return  this->mObjectType;
            }

            bool IsObjectExportable () const noexcept override
            {
                return this->mExportAllowed;
            }
        
            // CryptoObjectUid GetObjectId () const noexcept override
            // {   
            //     return  ks.GetPrototypedProps().Value().;
            // }
           
        
            CryptoAlgId GetPrimitiveId () const noexcept override
            {
                return    this->mAlgId ;
            }
        
            std::string GetKeyMaterialPath() const noexcept override
            {
                return    this->KeyMaterialPath;
            }
        
    


        };
    }
}
#endif /* CRYPTOPP_IO_INTERFACE_H_ */
