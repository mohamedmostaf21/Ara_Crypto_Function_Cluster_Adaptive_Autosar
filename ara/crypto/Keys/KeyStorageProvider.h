#ifndef _KEY_STORAGE_PROVIDER_H_
#define _KEY_STORAGE_PROVIDER_H_
#include"KeySlot.h"
#include <boost/property_tree/ptree_fwd.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream> 
#include <fstream>



namespace pt = boost::property_tree;
namespace ara
{
    namespace crypto
    {
        namespace keys
        {
            class KeyStorageProvider
            {  
                
            public:
                using Sptr = std::shared_ptr<KeyStorageProvider>;
                

                //ara::core::Result<TransactionId> BeginTransaction(const TransactionScope &targetSlots) noexcept;
                /*
                return  ara::core::Result<TransactionId>::FromValue(ID); 
                */

                //ara::core::Result<void> CommitTransaction(TransactionId id) noexcept;
                /*
                return  ara::core::Result<void>::FromValue(); 
                */
                void saveKey(const SymmetricKey& key, const std::string& filename);
                void saveKey(const PrivateKey& key, const std::string& filename);
                void saveKey(const PublicKey& key, const std::string& filename);


                ~KeyStorageProvider() noexcept = default;

               // UpdatesObserver::Sptr GetRegisteredObserver() const noexcept = 0;

                ara::core::Result<KeySlot> LoadKeySlot(ara::core::InstanceSpecifier &iSpecify) noexcept;

                KeyStorageProvider &operator=(const KeyStorageProvider &other) = default;

                KeyStorageProvider &operator=(KeyStorageProvider &&other) = default;
            private:
                static KeyStorageProvider::Sptr instance;      
            };
        }
    }
}

#endif /* _KEY_STORAGE_PROVIDER_H_ */