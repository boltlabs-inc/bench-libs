cmake_minimum_required (VERSION 2.8.11)
project (emp-sh2pc)
set(NAME "emp-sh2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-sh2pc DESTINATION include/)

# make a library with all our MPC primitives
add_library(token_utils build_tokens/sha256.cpp build_tokens/hmac.cpp build_tokens/ecdsa.cpp build_tokens/tokens.cpp build_tokens/tokens-misc.cpp)
target_link_libraries(token_utils ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${GMP_LIBRARIES} ${EMP-OT_LIBRARIES} )

# make executable that implements generate_tokens protocol
add_executable(token build_tokens/main.cpp)
target_link_libraries(token 
  ${EMP-OT_LIBRARIES} 
  token_utils)

# testing: not sure what the best structure is for this section
# this is NOT the usual cmake add_test function
macro (add_test _name)
  add_executable(${_name} "test/${_name}.cpp")
  target_link_libraries(${_name}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${GMP_LIBRARIES}
    ${EMP-OT_LIBRARIES}
    libcryptopp.a
    token_utils)
endmacro()

add_test (sha256)
add_test (ecdsa)
add_test (hmac)


