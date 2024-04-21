find_path(Crypto++_INCLUDE_DIR cryptopp)
find_library(Crypto++_LIBRARY NAMES cryptopp)

set(Crypto++_FOUND TRUE)
if(NOT Crypto++_LIBRARY OR NOT Crypto++_INCLUDE_DIR)
  set(Crypto++_FOUND FALSE)
endif()

if(Crypto++_FOUND)
  set(Crypto++_LIBRARIES ${Crypto++_LIBRARY})
  set(Crypto++_INCLUDE_DIRS ${Crypto++_INCLUDE_DIR})
endif()