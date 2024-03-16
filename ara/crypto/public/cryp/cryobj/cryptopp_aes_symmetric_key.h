#ifndef CRYPTOPP_AES_SUMMETRIC_KEY_H
#define CRYPTOPP_AES_SUMMETRIC_KEY_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include "cryptopp/files.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

#include "../../../private/cryp/cryobj/symmetric_key.h"

#define default_key_length_in_Byte  16 
#define min_key_length_in_Byte  16 
#define max_key_length_in_Byte  32 

namespace ara
{
    namespace crypto
    {
        namespace cryp
        {
            class CryptoPP_AES_SymmetricKey : public SymmetricKey
            {
            private:
                /*************** attributes *************/
                CryptoPP::SecByteBlock mValue;


            public:
                /************ constructor **************/
                CryptoPP_AES_SymmetricKey() : mValue(default_key_length_in_Byte)
                {

                }

                /*********/
                // Copy constructor
                CryptoPP_AES_SymmetricKey(const CryptoPP_AES_SymmetricKey& other) : mValue(other.mValue.size()) {
                    mValue.Assign(other.mValue, other.mValue.size());
                }


                CryptoPP_AES_SymmetricKey(const SymmetricKey& obj)
                { 
                   mValue = ((CryptoPP_AES_SymmetricKey)obj).mValue;
                }
                /********/


                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                static std::unique_ptr<SymmetricKey> createInstance() 
                {
                    std::unique_ptr<CryptoPP_AES_SymmetricKey> ptr = std::make_unique<CryptoPP_AES_SymmetricKey>();
                    
                    /*
                    CryptoPP::AutoSeededRandomPool prng;
                    prng.GenerateBlock(ptr->mValue, ptr->mValue.size());
                    */
                    std::string stringValue = "abcdabcdabcdabcd";
                    std::copy(stringValue.begin(), stringValue.end(), ptr->mValue.begin());

                    /*
                    std::cout << "/nmValue contents:" << std::endl;
                    for (size_t i = 0; i < ptr->mValue.size(); ++i) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ptr->mValue[i]) << " ";
                        if ((i + 1) % 16 == 0) {
                            std::cout << std::endl;
                        }
                    }
                    std::cout << std::dec << std::endl;                    
                    */

                    
                    return std::move(ptr);                    
                }

                /*************************************************************
                 * not autosar but until key storage provider is implemented
                **************************************************************/
                CryptoPP::SecByteBlock getKey()
                {
                    return mValue;
                }

                

                

                /************* override parent functions ************/

                virtual Usage GetAllowedUsage () const noexcept override
                {
                    return 5;
                }

                /*
                virtual COIdentifier GetObjectId () const noexcept override
                {
                    
                }

                virtual COIdentifier HasDependence () const noexcept override
                {
                    
                }
           
                virtual CryptoPrimitiveId::Uptr GetCryptoPrimitiveId () const noexcept override
                {
                    
                }
                
                virtual std::size_t GetPayloadSize () const noexcept override
                {
                    
                }
                
                virtual bool IsExportable () const noexcept override
                {
                    
                }
                
                virtual bool IsSession () const noexcept override
                {
                    
                }
                
                virtual ara::core::Result<void> Save (IOInterface &container) const noexcept override
                {
                    
                }
                */
            };
        }
    }
}


#endif