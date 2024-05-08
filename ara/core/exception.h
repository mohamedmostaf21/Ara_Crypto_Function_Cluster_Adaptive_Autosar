#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <exception>
#include "error_code.h"

namespace ara
{
    namespace core
    {
        /*
        class Exception : public std::exception 
        {
            public:
                explicit Exception (ErrorCode err) noexcept;

                const char* what () const noexcept override;

                const ErrorCode& Error () const noexcept;

                Exception& operator= (Exception const &other);
        };
        */
       

       class Exception : public std::exception 
       { 
        private:
            /************ attributes ************/
            ErrorCode* mError;
            
        public:
            /********** constructor *************/
            explicit Exception(ErrorCode err) noexcept : mError(new ErrorCode(err)) {}


            /************* fundemental functions **********/
            const char* what() const noexcept override {
                //return "Custom Exception";
                return mError->Message().c_str();
            }


            /************* getter *************************/
            const ErrorCode& Error() const noexcept {
                return *mError;
            }


            /*************** assigment operator ***********/
            Exception& operator=(Exception const& other)
            {
                if (this != &other) {
                    mError = new ErrorCode(other.Error());
                }
                return *this;
            }

            /********* deconstructor ***********/
            ~Exception() {
                delete mError;
            }
        };
    }
}

#endif
