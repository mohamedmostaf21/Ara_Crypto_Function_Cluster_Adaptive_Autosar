#ifndef KEY_STORAGE_PROVIDER_h
#define KEY_STORAGE_PROVIDER_h

#include "../../../core/instance_specifier.h"
#include "elementary_types.h"
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "../../private/cryp/cryobj/symmetric_key.h"
#include "../../private/cryp/cryobj/private_key.h"
#include "../../private/cryp/cryobj/public_key.h"

namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            using namespace cryp;
            class KeyStorageProvider
            {
            public:
                using Sptr = std::shared_ptr<KeyStorageProvider>;
                static KeyStorageProvider::Sptr instance; 

                virtual ara::core::Result<KeySlot::Uptr> LoadKeySlot (ara::core::InstanceSpecifier &iSpecify) noexcept=0;

                virtual ara::core::Result<TransactionId> BeginTransaction (const TransactionScope &targetSlots) noexcept=0;

                virtual ara::core::Result<void> CommitTransaction (TransactionId id) noexcept=0;
                


                //virtual UpdatesObserver::Uptr GetRegisteredObserver () const noexcept=0;

                //virtual UpdatesObserver::Uptr RegisterObserver (UpdatesObserver::Uptr observer=nullptr) noexcept=0;

                //virtual ara::core::Result<void> RollbackTransaction (TransactionId id) noexcept=0;

                //virtual ara::core::Result<void> UnsubscribeObserver (KeySlot &slot) noexcept=0;

                virtual  void  saveKey(const SymmetricKey& key, const std::string& filename) =0;
                virtual void  saveKey(const PrivateKey& key, const std::string& filename) =0; 
                virtual void  saveKey(const PublicKey& key, const std::string& filename) =0; 
                KeyStorageProvider& operator= (const KeyStorageProvider &other)=default;

                KeyStorageProvider& operator= (KeyStorageProvider &&other)=default;	
                
                virtual ~KeyStorageProvider () noexcept=default;
            };
        }
    }
}


#endif