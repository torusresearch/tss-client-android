
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

project(DKLS)

set(libs_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)

add_library(
        DKLS
        STATIC
        IMPORTED
)

set_target_properties(
        DKLS
        PROPERTIES
        IMPORTED_LOCATION ${libs_DIR}/${ANDROID_ABI}/libdkls.a
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(
        dkls-native SHARED
        jniChaChaRng.cpp
        jniCounterparties.cpp
        jniDKLSComm.cpp
        jniPrecompute.cpp
        jniSignatureFragments.cpp
        jniThresholdSigner.cpp
        jniUtilities.cpp
        jniCommon.cpp
)

find_library(
        log-lib
        log
)

target_include_directories(
        dkls-native PRIVATE ${libs_DIR}/
)

target_link_libraries(
        dkls-native
        android
        tkey
        ${log-lib}
        "-Wl,--allow-multiple-definition"
)
