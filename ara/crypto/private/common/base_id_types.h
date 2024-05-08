#ifndef BASE_ID_TYPES_H
#define BASE_ID_TYPES_H

#include <cstdint>
#include "../../../core/vector.h"

namespace ara
{
    namespace crypto
    {
        using ByteVector = ara::core::Vector<std::uint8_t>;
        using AllowedUsageFlags = std::uint32_t;
        using CryptoAlgId = std::uint64_t;


        enum class CryptoObjectType : std::uint32_t 
        {
            kUndefined= 0,
            kSymmetricKey= 1,
            kPrivateKey= 2,
            kPublicKey= 3,
            kSignature= 4,
            kSecretSeed= 5
        };

        enum class ProviderType : std::uint32_t 
        {
            kUndefinedProvider= 0,
            kCryptoProvider= 1,
            kKeyStorageProvider= 2,
            kX509Provider= 3
        };

        enum class CryptoTransform : std::uint32_t 
        {
            kEncrypt= 1,
            kDecrypt= 2,
            kMacVerify= 3,
            kMacGenerate= 4,
            kWrap= 5,
            kUnwrap= 6,
            kSigVerify= 7,
            kSigGenerate= 8
        };

        enum class KeySlotType : std::uint32_t
        {
            kMachine= 1,
            kApplication= 2
        };

        const CryptoAlgId kAlgIdUndefined = 0u;
        const CryptoAlgId kAlgIdAny = kAlgIdUndefined;
        const CryptoAlgId kAlgIdDefault = kAlgIdUndefined;
        const CryptoAlgId kAlgIdNone = kAlgIdUndefined;
        const AllowedUsageFlags kAllowPrototypedOnly = 0;
        const AllowedUsageFlags kAllowDataEncryption = 0x0001;
        const AllowedUsageFlags kAllowDataDecryption = 0x0002;
        const AllowedUsageFlags kAllowExactModeOnly = 0x8000;
        const AllowedUsageFlags kAllowKdfMaterial = 0x0080;
        const AllowedUsageFlags kAllowKeyAgreement = 0x0010;
        const AllowedUsageFlags kAllowKeyDiversify = 0x0020;
        const AllowedUsageFlags kAllowKeyExporting = 0x0100;
        const AllowedUsageFlags kAllowKeyImporting = 0x0200;
        const AllowedUsageFlags kAllowRngInit = 0x0040;
        const AllowedUsageFlags kAllowSignature = 0x0004;
        const AllowedUsageFlags kAllowVerification = 0x0008;
        const AllowedUsageFlags kAllowDerivedDataDecryption = kAllowDataDecryption << 16;
        const AllowedUsageFlags kAllowDerivedDataEncryption = kAllowDataEncryption << 16;
        const AllowedUsageFlags kAllowDerivedRngInit = kAllowRngInit << 16;
        const AllowedUsageFlags kAllowDerivedExactModeOnly = kAllowExactModeOnly << 16;
        const AllowedUsageFlags kAllowDerivedKdfMaterial = kAllowKdfMaterial << 16;
        const AllowedUsageFlags kAllowDerivedKeyDiversify = kAllowKeyDiversify << 16;
        const AllowedUsageFlags kAllowDerivedKeyExporting = kAllowKeyExporting << 16;
        const AllowedUsageFlags kAllowDerivedKeyImporting = kAllowKeyImporting << 16;
        const AllowedUsageFlags kAllowDerivedSignature = kAllowSignature << 16;
        const AllowedUsageFlags kAllowDerivedVerification = kAllowVerification << 16;
        const AllowedUsageFlags kAllowKdfMaterialAnyUsage = kAllowKdfMaterial | kAllowDerivedDataEncryption 
                                                                            | kAllowDerivedDataDecryption 
                                                                            | kAllowDerivedSignature 
                                                                            | kAllowDerivedVerification 
                                                                            | kAllowDerivedKeyDiversify 
                                                                            | kAllowDerivedRngInit 
                                                                            | kAllowDerivedKdfMaterial 
                                                                            | kAllowDerivedKeyExporting 
                                                                            | kAllowDerivedKeyImporting;
    }
}
#endif