#ifndef INSTANCE_IDENTIFIER_H
#define INSTANCE_IDENTIFIER_H

#include <string>

namespace ara
{
    namespace com
    {
        class InstanceIdentifier
        {
        private:
            /**************** attributes ***********************/
           
            std::string instance_id_;
        
        public:
            /**************** constructor **********************/
           
            explicit InstanceIdentifier(std::string value): instance_id_(value)
            {}



            /************** getters ****************************/
           
            std::string ToString() const
            {
                return instance_id_;
            }

            uint16_t getInstanceId()
            {
                return std::stoi(instance_id_);
            }
            
            
            /******************** deconstructor ***************/

            ~InstanceIdentifier() = default;
        };

    }   
} 

#endif