find_path(Boost_INCLUDE_DIR boost)
find_library(Boost_LIBRARY NAMES boost)

set(Boost_FOUND TRUE)
if(NOT Boost_LIBRARY OR NOT Boost_INCLUDE_DIR)
  set(Boost_FOUND FALSE)
endif()

if(Boost_FOUND)
  set(Boost_LIBRARIES ${Boost_LIBRARY})
  set(Boost_INCLUDE_DIRS ${Boost_INCLUDE_DIR})
endif()