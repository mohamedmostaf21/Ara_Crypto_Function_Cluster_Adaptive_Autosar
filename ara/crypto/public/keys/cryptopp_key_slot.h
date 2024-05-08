#ifndef CRYPTOPP_KEY_SLOT_H
#define CRYPTOPP_KEY_SLOT_H
#include "../../private/keys/keyslot.h"
#include "../common/cryptopp_io_interface.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/secblock.h"
using namespace std;
namespace ara
{
    namespace crypto
    {

        namespace keys
        {
            class Cryptopp_KeySlot : public KeySlot
            {
                private:
                std::string  InstanceSpecifier;
                std::string  CryptoProvider;
                std::string  KeyMaterialPath;
                KeySlotPrototypeProps props;
                CryptoAlgId  AlgId;
                bool isempty;    
                bool modified;
                bool reserveSpareSlot;
            
             public:
                void setmeta(std::string  InstanceSpecifier,std::string  CryptoProvider,std::string  KeyMaterialPath, CryptoAlgId  AlgId, crypto::AllowedUsageFlags  AllowedUsageFlags, crypto::CryptoObjectType   CryptoObjectType,bool  Exportable,KeySlotType  SlotType,std::size_t  SlotCapacity,bool  AllocateShadowCopy,bool  AllowContentTypeChange,int32_t  MaxUpdateAllowed) override
                {
                    this->InstanceSpecifier = InstanceSpecifier;
                    this->CryptoProvider = CryptoProvider;
                    this->KeyMaterialPath = KeyMaterialPath;

                    props.mAlgId = AlgId;
                    props.mAllocateSpareSlot = AllocateShadowCopy;
                    props.mAllowContentTypeChange = AllowContentTypeChange;
                    props.mContentAllowedUsage = AllowedUsageFlags;
                    props.mExportAllowed = Exportable;
                    props.mMaxUpdateAllowed = MaxUpdateAllowed;
                    props.mObjectType = CryptoObjectType;
                    props.mSlotCapacity = SlotCapacity;
                    props.mSlotType = SlotType;
                   

                    this->isempty = true;
                    this->modified = true;
                }
                bool IsEmpty() const noexcept override
                {
                    return isempty;
                }
       
          
                std::string ToString(const crypto::CryptoObjectType& cryptoObject) const
                {
                    if(cryptoObject == CryptoObjectType::kSymmetricKey){
                         return "kSymmetricKey";
                    }else if(cryptoObject == CryptoObjectType::kPrivateKey){
                         return "kPrivateKey";
                    }else if(cryptoObject == CryptoObjectType::kPublicKey){
                         return "kPublicKey";
                    }else if(cryptoObject == CryptoObjectType::kSignature){
                         return "kSignature";
                    }else if (cryptoObject == CryptoObjectType::kSecretSeed){
                        return   "kSecretSeed";
                    }else{
                        return "kUndefined";
                    }
                    
         
                }

                std::string ToString(const crypto::KeySlotType& slotType) const
                {
                    if(slotType == KeySlotType::kApplication){
                         return "kApplication";
                    }else {
                        return "kMachine";
                    }
                
                }
                KeySlotType GetSlotType(std::string slotType)
                {
                    if(slotType == "kApplication"){
                        return  KeySlotType::kApplication;
                    }else {
                        return KeySlotType::kMachine;
                    }
                    
                }

                CryptoObjectType GetObjectType(std::string object)
                {
                   if(object == "kSymmetricKey"){
                        return CryptoObjectType::kSymmetricKey;
                    }else if(object == "kPrivateKey"){
                        return CryptoObjectType::kPrivateKey;
                    }else if(object ==  "kPublicKey"){
                         return CryptoObjectType::kPublicKey;
                    }else if(object == "kSignature"){
                         return CryptoObjectType::kSignature;
                    }else if (object == "kSecretSeed"){
                        return   CryptoObjectType::kSecretSeed;
                    }else{
                        return CryptoObjectType::kUndefined;
                    }
                }
                
                std::string boolToString(bool flag) const noexcept{
                    if(flag){
                        return "true";
                    }else{
                        return "false";
                    }
                }
                void printData() const noexcept
                {
                    cout<<"InstanceSpecifier = "<< InstanceSpecifier << endl;
                    cout<<"CryptoProvider = "<< CryptoProvider << endl;
                    cout<<"KeyMaterialPath = "<< KeyMaterialPath << endl;
                    cout<<"AlgId = "<< props.mAlgId << endl;
                    printf("AllowedUsageFlags = 0x%x\n", props.mContentAllowedUsage);
                    cout<<"CryptoObjectType = "<< ToString(props.mObjectType) << endl;
                    cout<<"Exportable = "<< boolToString(props.mExportAllowed) << endl;
                    cout<<"SlotType = "<< ToString(props.mSlotType) << endl;
                    cout<<"SlotCapacity = "<< props.mSlotCapacity << endl;
                    cout<<"AllocateShadowCopy = "<< boolToString(props.mAllocateSpareSlot) << endl;
                    cout<<"AllowContentTypeChange = "<< boolToString(props.mAllowContentTypeChange) << endl;
                    cout<<"MaxUpdateAllowed = "<< props.mMaxUpdateAllowed << endl;

                }

                ara::core::Result<KeySlotPrototypeProps> GetPrototypedProps () const noexcept
                {
                    return ara::core::Result<KeySlotPrototypeProps>::FromValue(props);
                }
                ara::core::Result<IOInterface::Uptr> Open (bool subscribeForUpdates, bool writeable) const noexcept override
                {
                    // Check if the slot is already opened with write access
                    if (writeable && !IsEmpty()) {
                        return ara::core::Result<IOInterface::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kBusyResource, NoSupplementaryDataForErrorDescription));
                    }

                    // Check if the slot has been modified after it was opened
                    if (!IsEmpty() && IsModified()) {
                        return   ara::core::Result<IOInterface::Uptr>::FromError(ara::crypto::MakeErrorCode(CryptoErrorDomain::Errc::kModifiedResource, NoSupplementaryDataForErrorDescription));
                    }

                    // In a real implementation, perform actual opening operations here

                    // For demonstration purposes, let's just print a message
                    std::cout << "Opening key slot..." << std::endl;

                    // Construct IOInterface smart pointer, this could be replaced with actual implementation
                    IOInterface::Uptr ioInterface = std::make_unique<crypto::CryptoPP_IOInterface>(KeyMaterialPath, props);
                    
                    // Simulate success by returning an IOInterface smart pointer
                    auto result = ara::core::Result<IOInterface::Uptr>::FromValue(std::move(ioInterface));

                    // If subscribeForUpdates is true, notify UpdatesObserver
                    if (subscribeForUpdates) {
                        // In a real implementation, call method to notify UpdatesObserver
                        // For demonstration purposes, let's just print a message
                        std::cout << "Notifying UpdatesObserver..." << std::endl;
                    }
                   
                    return result;

                }
                    
                
                bool IsModified() const noexcept {
                    // Return the value of the member variable indicating modification state
                    return modified;
                }
            };
         

            
        }
    }
}               

#endif /* CRYPTOPP_KEY_SLOT_H */
