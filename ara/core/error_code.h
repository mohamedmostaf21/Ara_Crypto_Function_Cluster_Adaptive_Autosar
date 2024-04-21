#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include <string>
#include "error_domain.h"
#include <stdexcept>
#include <iostream>

namespace ara
{
    namespace core
    {
        /// @brief A wrapper around the raw error code in a specific ErrorDomain
        class ErrorCode final
        {
        private:
            ErrorDomain::CodeType mValue;    // uint32_t mValue
            const ErrorDomain& mDomain;      // uint64_t mDomain

        public:
            /************ constructor *******************/
            /// @brief Constructor
            /// @param value Error code value
            /// @param domain Error code domain
            constexpr ErrorCode( ErrorDomain::CodeType value,
                                 const ErrorDomain &domain
                               ) noexcept : mValue{value}, mDomain{domain}
            {
            
            }

           
            /*************** getters ***************/
            /// @brief Get error code value
            /// @returns Raw error code value
            constexpr ErrorDomain::CodeType Value() const noexcept
            {
                return mValue;
            }

            /// @brief Get error code domain
            /// @returns Error domain which the error code belongs to
            constexpr ErrorDomain const &Domain() const noexcept
            {
                return mDomain;
            }

            /********* equal and not equal operators **********/
            constexpr bool operator==(const ErrorCode &other) const noexcept
            {
                return mDomain == other.mDomain && mValue == other.mValue;
            }

            constexpr bool operator!=(const ErrorCode &other) const noexcept
            {
                return mDomain != other.mDomain || mValue != other.mValue;
            }


            /// @brief Get error message
            /// @returns Error code corresponding message in the defined domain
            std::string Message() const noexcept
            {
                //std::cout << "ssssss\n";
                std::string _result(mDomain.Message(mValue));
                return _result;    
            }


            /// @brief Throw the error as an exception
            void ThrowAsException() const
            {
                std::runtime_error _exception{Message()};
                throw _exception;
            }


            /********* disable empty constructor *********/
            ErrorCode() = delete;
            
            
            /****** tell compiler to generate default empty constructor *****/
            ~ErrorCode() noexcept = default;
        };
    }
}

#endif