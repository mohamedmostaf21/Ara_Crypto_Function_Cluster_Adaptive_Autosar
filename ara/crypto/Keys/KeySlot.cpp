#include "KeySlot.h"

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
                void KeySlot::setmeta(std::string  InstanceSpecifier,std::string  CryptoProvider,std::string  KeyMaterialPath, CryptoAlgId  AlgId, crypto::AllowedUsageFlags  AllowedUsageFlags, crypto::CryptoObjectType   CryptoObjectType,bool  Exportable,KeySlotType  SlotType,std::size_t  SlotCapacity,bool  AllocateShadowCopy,bool  AllowContentTypeChange,int32_t  MaxUpdateAllowed)
                {
                    this->InstanceSpecifier = InstanceSpecifier;
                    this->CryptoProvider = CryptoProvider;
                    this->KeyMaterialPath = KeyMaterialPath;
                    this->AlgId = AlgId;
                    this->AllowedUsageFlags = AllowedUsageFlags;
                    this->Crypto_Object_Type = CryptoObjectType;
                    this->Exportable = Exportable;
                    this->SlotType = SlotType;
                    this->SlotCapacity = SlotCapacity;
                    this->AllocateShadowCopy = AllocateShadowCopy;
                    this->AllowContentTypeChange = AllowContentTypeChange;
                    this->MaxUpdateAllowed = MaxUpdateAllowed;
                    this->isempty = true;
                    this->modified = true;
                }
                bool KeySlot::IsEmpty() const noexcept
                {
                    return isempty;
                }
       
          
                std::string KeySlot::ToString(const crypto::CryptoObjectType& cryptoObject) const
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

                std::string KeySlot::ToString(const crypto::KeySlotType& slotType) const
                {
                    if(slotType == KeySlotType::kApplication){
                         return "kApplication";
                    }else {
                        return "kMachine";
                    }
                
                }
                KeySlotType KeySlot::GetSlotType(std::string slotType)
                {
                    if(slotType == "kApplication"){
                        return  KeySlotType::kApplication;
                    }else {
                        return KeySlotType::kMachine;
                    }
                    
                }

                CryptoObjectType KeySlot::GetObjectType(std::string object)
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
                
                std::string KeySlot::boolToString(bool flag) const noexcept{
                    if(flag){
                        return "true";
                    }else{
                        return "false";
                    }
                }
                void KeySlot::KeySlotContentProps() const noexcept
                {
                    cout<<"InstanceSpecifier = "<< InstanceSpecifier << endl;
                    cout<<"CryptoProvider = "<< CryptoProvider << endl;
                    cout<<"KeyMaterialPath = "<< KeyMaterialPath << endl;
                    cout<<"AlgId = "<< AlgId << endl;
                    printf("AllowedUsageFlags = 0x%x\n", AllowedUsageFlags);
                    cout<<"CryptoObjectType = "<< ToString(Crypto_Object_Type) << endl;
                    cout<<"Exportable = "<< boolToString(Exportable) << endl;
                    cout<<"SlotType = "<< ToString(SlotType) << endl;
                    cout<<"SlotCapacity = "<< SlotCapacity << endl;
                    cout<<"AllocateShadowCopy = "<< boolToString(AllocateShadowCopy) << endl;
                    cout<<"AllowContentTypeChange = "<< boolToString(AllowContentTypeChange) << endl;
                    cout<<"MaxUpdateAllowed = "<< MaxUpdateAllowed << endl;

                }

                ara::core::Result<KeySlotPrototypeProps> KeySlot::GetPrototypedProps () const noexcept
                {
                    KeySlotPrototypeProps props;
                    props.mAlgId = AlgId;
                    props.mAllocateSpareSlot = AllocateShadowCopy;
                    props.mAllowContentTypeChange = AllowContentTypeChange;
                    props.mContentAllowedUsage = AllowedUsageFlags;
                    props.mExportAllowed = Exportable;
                    props.mMaxUpdateAllowed = MaxUpdateAllowed;
                    props.mObjectType = Crypto_Object_Type;
                    props.mSlotCapacity = SlotCapacity;
                    props.mSlotType = SlotType;
                    return ara::core::Result<KeySlotPrototypeProps>::FromValue(props);
                }
                ara::core::Result<IOInterface::Uptr> KeySlot::Open (bool subscribeForUpdates, bool writeable) const
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
                    IOInterface::Uptr ioInterface = std::make_unique<crypto::CryptoPP_IOInterface>();
                    ioInterface->setInterface(AllowedUsageFlags, SlotCapacity, Crypto_Object_Type, AlgId, Exportable, KeyMaterialPath);
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
                    
                // IOInterface::Uptr KeySlot::get_io_interface()
                // {
                //     return std::move(this->ioInterface);

                // }
                bool KeySlot::IsModified() const noexcept {
                    // Return the value of the member variable indicating modification state
                    return modified;
                 }

            
        }
    }
}               