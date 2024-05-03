#ifndef UPDATES_OBSERVER_H_
#define UPDATES_OBSERVER_H_
#include "stdlib.h"
#include "elementary_types.h"
namespace ara {
    namespace crypto {
        namespace keys{
            class UpdatesObserver 
            {
            public:
                using Uptr = std::unique_ptr<UpdatesObserver>;

                virtual ~UpdatesObserver () noexcept=default;
                
                virtual void OnUpdate (const TransactionScope &updatedSlots) noexcept=0;

                UpdatesObserver& operator= (const UpdatesObserver &other)=default;
                
                UpdatesObserver& operator= (UpdatesObserver &&other)=default;
            };
        }
    }
}


#endif /* UPDATES_OBSERVER_H_ */
