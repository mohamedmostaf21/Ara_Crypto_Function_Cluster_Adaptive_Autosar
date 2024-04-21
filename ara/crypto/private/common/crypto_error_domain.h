#ifndef CRYPTO_ERROR_DOMAIN_H
#define CRYPTO_ERROR_DOMAIN_H

#include "../../../core/error_domain.h"
#include "../../../core/error_code.h"
#include "../../../core/exception.h"

namespace ara
{
    namespace crypto
    {
        enum class CryptoErrc : ara::core::ErrorDomain::CodeType 
        {
            kErrorClass= 0x1000000,
            kErrorSubClass= 0x10000,
            kErrorSubSubClass= 0x100,
            kResourceFault= 1 * kErrorClass,
            kBusyResource= kResourceFault + 1,
            kInsufficientResource= kResourceFault + 2,
            kUnreservedResource= kResourceFault + 3,
            kModifiedResource= kResourceFault + 4,
            kLogicFault= 2 * kErrorClass,
            kInvalidArgument= kLogicFault + 1 * kErrorSubClass,
            kUnknownIdentifier= kInvalidArgument + 1,
            kInsufficientCapacity= kInvalidArgument + 2,
            kInvalidInputSize= kInvalidArgument + 3,
            kIncompatibleArguments= kInvalidArgument + 4,
            kInOutBuffersIntersect= kInvalidArgument + 5,
            kBelowBoundary= kInvalidArgument + 6,
            kAboveBoundary= kInvalidArgument + 7,
            kAuthTagNotValid= kInvalidArgument + 8,
            kUnsupported= kInvalidArgument + 1 *kErrorSubSubClass,
            kInvalidUsageOrder= kLogicFault + 2 *kErrorSubClass,
            kUninitializedContext= kInvalidUsageOrder + 1,
            kProcessingNotStarted= kInvalidUsageOrder + 2,
            kProcessingNotFinished= kInvalidUsageOrder + 3,
            kRuntimeFault= 3 * kErrorClass,
            kUnsupportedFormat= kRuntimeFault + 1,
            kBruteForceRisk= kRuntimeFault + 2,
            kContentRestrictions= kRuntimeFault + 3,
            kBadObjectReference= kRuntimeFault + 4,
            kContentDuplication= kRuntimeFault + 6,
            kUnexpectedValue= kRuntimeFault + 1 * kErrorSubClass,
            kIncompatibleObject= kUnexpectedValue + 1,
            kIncompleteArgState= kUnexpectedValue + 2,
            kEmptyContainer= kUnexpectedValue + 3,
            kMissingArgument= kUnexpectedValue + 4,
            kBadObjectType= kUnexpectedValue + 1*kErrorSubSubClass,
            kUsageViolation= kRuntimeFault + 2*kErrorSubClass,
            kAccessViolation= kRuntimeFault + 3 *kErrorSubClass
        };

        class CryptoException : public ara::core::Exception
        {
        public:
            explicit CryptoException (ara::core::ErrorCode err) noexcept : Exception(err)
            {

            }
        };

        class CryptoErrorDomain final : public ara::core::ErrorDomain
        {
        public:
            using Errc = CryptoErrc;
            using Exception = CryptoException;
            
            /********** constructor ********/
            constexpr CryptoErrorDomain () noexcept: ErrorDomain(ara::core::ErrorDomain::CRYPTO_DOMAIN)
            {

            }
            
            /*********** override parent functions */
            const char* Name () const noexcept override
            {
                return "Crypto";
            }
            
            const char* Message (ara::core::ErrorDomain::CodeType errorCode) const noexcept override
            {
                CryptoErrc cryptoErrorCode = static_cast<CryptoErrc>(errorCode);
                switch (cryptoErrorCode) {
                    case CryptoErrc::kResourceFault:
                        return "kResourceFault";
                        break;
                    case CryptoErrc::kBusyResource:
                        return "kBusyResource";
                        break;
                    case CryptoErrc::kInsufficientResource:
                        return "kInsufficientResource";
                        break;
                    case CryptoErrc::kUnreservedResource:
                        return "kUnreservedResource";
                        break;
                    case CryptoErrc::kModifiedResource:
                        return "kModifiedResource";
                        break;
                    case CryptoErrc::kLogicFault:
                        return "kLogicFault";
                        break;
                    case CryptoErrc::kInvalidArgument:
                        return "kInvalidArgument";
                        break;
                    case CryptoErrc::kUnknownIdentifier:
                        return "kUnknownIdentifier";
                        break;
                    case CryptoErrc::kInsufficientCapacity:
                        return "kInsufficientCapacity";
                        break;
                    case CryptoErrc::kInvalidInputSize:
                        return "kInvalidInputSize";
                        break;
                    case CryptoErrc::kIncompatibleArguments:
                        return "Incompatible Arguments";
                        break;
                    case CryptoErrc::kInOutBuffersIntersect:
                        return "InOutBuffers Intersect";
                        break;
                    case CryptoErrc::kBelowBoundary:
                        return "Below Boundary";
                        break;
                    case CryptoErrc::kAboveBoundary:
                        return "kAboveBoundary";
                        break;
                    case CryptoErrc::kAuthTagNotValid:
                        return "AuthTagNotValid";
                        break;
                    case CryptoErrc::kUnsupported:
                        return "Unsupported";
                        break;
                    case CryptoErrc::kInvalidUsageOrder:
                        return "kInvalidUsageOrder";
                        break;
                    case CryptoErrc::kUninitializedContext:
                        return "kUninitializedContext";
                        break;
                    case CryptoErrc::kProcessingNotStarted:
                        return "kProcessingNotStarted";
                        break;
                    case CryptoErrc::kProcessingNotFinished:
                        return "kProcessingNotFinished";
                        break;
                    case CryptoErrc::kRuntimeFault:
                        return "kRuntimeFault";
                        break;
                    case CryptoErrc::kUnsupportedFormat:
                        return "kUnsupportedFormat";
                        break;
                    case CryptoErrc::kBruteForceRisk:
                        return "kBruteForceRisk";
                        break;
                    case CryptoErrc::kContentRestrictions:
                        return "kContentRestrictions";
                        break;
                    case CryptoErrc::kBadObjectReference:
                        return "kBadObjectReference";
                        break;
                    case CryptoErrc::kContentDuplication:
                        return "kContentDuplication";
                        break;
                    case CryptoErrc::kUnexpectedValue:
                        return "kUnexpectedValue";
                        break;
                    case CryptoErrc::kIncompatibleObject:
                        return "kIncompatibleObject";
                        break;
                    case CryptoErrc::kIncompleteArgState:
                        return "kIncompleteArgState";
                        break;
                    case CryptoErrc::kEmptyContainer:
                        return "kEmptyContainer";
                        break;
                    case CryptoErrc::kMissingArgument:
                        return "kMissingArgument";
                        break;
                    case CryptoErrc::kBadObjectType:
                        return "kBadObjectType";
                        break;
                    case CryptoErrc::kUsageViolation:
                        return "kUsageViolation";
                        break;
                    case CryptoErrc::kAccessViolation:
                        return "kAccessViolation";
                        break;
                    default:
                        return "Unknown error code";
                }
            }

            /*
            void ThrowAsException (const ara::core::ErrorCode &errorCode) const override
            {
                throw Exception(errorCode);
            }*/
        };

        /*
        Makes Error Code instances from the Crypto Error Domain. The returned ErrorCode instance
        always references to CryptoErrorDomain
        */
        static CryptoErrorDomain _obj;
        constexpr ara::core::ErrorCode MakeErrorCode( CryptoErrorDomain::Errc code,
                                                        ara::core::ErrorDomain::SupportDataType data
                                                    ) noexcept
        {
            /* 
            Segmetation fault incase of uncomment the following line an _obj is passed 
            by refence and will be destroyed after this call
            */
            //CryptoErrorDomain _obj;
            
            ara::core::ErrorCode _result( (ara::core::ErrorDomain::CodeType)code, _obj);
            return _result;
        }
    }
}


#endif