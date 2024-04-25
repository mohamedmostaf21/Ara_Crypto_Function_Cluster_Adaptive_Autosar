#ifndef SET_KEY_STATE_H
#define SET_KEY_STATE_H

namespace ara
{
    namespace crypto
    {
        namespace helper
        {
            /*
                this helper class doesnot be mentioned in autosar 
            */
            enum class setKeyState
            {
                CALLED,
                NOT_CALLED
            };

            /*
            this helper class doesnot be mentioned in autosar 
            */
            enum class calling
            {
                START_IS_NOT_CALLED,
                START_IS_CALLED,
                UPDATE_IS_CALLED,
                FINISH_IS_CALLED
            };
        }

        
    }
}

#endif