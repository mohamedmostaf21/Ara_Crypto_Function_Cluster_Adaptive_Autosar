cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 20)
project(Demo)

# Include the directory containing FindCrypto++.cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})
# Find the Crypto++ package
find_package(Crypto++ REQUIRED)


add_library(
   Crypto

   ## core ##
   ara/core/error_code.h
   ara/core/error_domain.h
   ara/core/exception.h
   ara/core/instance_id.h
   ara/core/instance_specifier.h
   ara/core/instance_specifier.cpp
   ara/core/optional.h
   ara/core/result.h
   ara/core/SamplePtr.h
   ara/core/Span.h
   ara/core/StringView.h
   ara/core/utility.h
   ara/core/vector.h

   ####### helper ######### 
   ara/crypto/helper/state.h

   ####### private ########
   ## common
   ara/crypto/private/common/base_id_types.h
   ara/crypto/private/common/crypto_error_domain.h
   ara/crypto/private/common/crypto_object_uid.h
   ara/crypto/private/common/mem_region.h
   ara/crypto/private/common/uuid.h


   ## cryp/cryobj
   ara/crypto/private/cryp/cryobj/crypto_object.h
   ara/crypto/private/cryp/cryobj/crypto_primitive_id.h
   ara/crypto/private/cryp/cryobj/private_key.h
   ara/crypto/private/cryp/cryobj/public_key.h
   ara/crypto/private/cryp/cryobj/restricted_use_object.h
   ara/crypto/private/cryp/cryobj/secret_seed.h
   ara/crypto/private/cryp/cryobj/symmetric_key.h
  

   ## cryp
   ara/crypto/private/cryp/crypto_context.h
   ara/crypto/private/cryp/decryptor_private_ctx.h
   ara/crypto/private/cryp/encryptor_public_ctx.h
   ara/crypto/private/cryp/extension_service.h
   ara/crypto/private/cryp/hash_function_ctx.h
   ara/crypto/private/cryp/random_generator_ctx.h
   ara/crypto/private/cryp/signature_service.h
   ara/crypto/private/cryp/symmetric_block_cipher_ctx.h
   

   
   ######### public ##########
   ara/crypto/public/cryp/cryobj/cryptopp_aes_symmetric_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_crypto_primitive_id.h
   ara/crypto/public/cryp/cryobj/cryptopp_rsa_private_key.h
   ara/crypto/public/cryp/cryobj/cryptopp_rsa_public_key.h
   ara/crypto/public/cryp/cryobj/loadKey.h


   ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.h
   ara/crypto/public/cryp/cryptopp_sha_256_hash_function_ctx.cpp

   ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.h
   ara/crypto/public/cryp/cryptopp_aes_symmetric_block_cipher_ctx.cpp

   ara/crypto/public/cryp/cryptopp_random_generator_ctx.h
   ara/crypto/public/cryp/cryptopp_random_generator_ctx.cpp

   ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.h
   ara/crypto/public/cryp/cryptopp_rsa_2046_encryptor_public_ctx.cpp

   ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.h
   ara/crypto/public/cryp/cryptopp_rsa_2046_decryptor_private_ctx.cpp
)

###################################################
#              executables on CryptoPP            #
###################################################

# aes_cbc example using CryptoPP
add_executable(aes CryptoPP_examples/AES_CBC_128.cpp)
target_include_directories(aes PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(aes ${Crypto++_LIBRARIES})

# sha256 example using CryptoPP
add_executable(sha256 CryptoPP_examples/SHA_256.cpp)
target_include_directories(sha256 PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(sha256 ${Crypto++_LIBRARIES})


## key generation example  using CryptoPP
add_executable(keysGeneration CryptoPP_examples/PUK_PRK_generation.cpp)
target_include_directories(keysGeneration PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(keysGeneration ${Crypto++_LIBRARIES})

## rsa example  using CryptoPP
add_executable(rsa CryptoPP_examples/RAS_2048.cpp)
target_include_directories(rsa PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(rsa ${Crypto++_LIBRARIES})


###################################################
#            executables for trying              #
###################################################

add_executable(ex_span samples/example_span.cpp)

add_executable(ex_result samples/example_result.cpp)
target_link_libraries(ex_result Crypto)

add_executable(ex_uuid samples/example_uuid.cpp)
target_link_libraries(ex_uuid Crypto)


###################################################
#                  executables on crypto          #
###################################################

add_executable(ex_hash samples/example_hashctx.cpp)
target_link_libraries(ex_hash ${Crypto++_LIBRARIES})
target_link_libraries(ex_hash Crypto)

add_executable(ex_aes samples/example_summetric_block_cipher.cpp)
target_link_libraries(ex_aes ${Crypto++_LIBRARIES})
target_link_libraries(ex_aes Crypto)


add_executable(ex_rsa samples/example_rsa_contexts.cpp)
target_link_libraries(ex_rsa ${Crypto++_LIBRARIES})
target_link_libraries(ex_rsa Crypto)

add_executable(randomGen /home/mohamed/Crypto/samples/example_random_generator_ctx.cpp)
target_include_directories(randomGen PUBLIC ${Crypto++_INCLUDE_DIRS})
target_link_libraries(randomGen ${Crypto++_LIBRARIES})

target_link_libraries(randomGen Crypto)