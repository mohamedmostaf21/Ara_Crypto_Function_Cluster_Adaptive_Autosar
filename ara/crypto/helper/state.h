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
        }
    }
}

#endif