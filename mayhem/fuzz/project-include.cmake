# Passed as -DCMAKE_PROJECT_INCLUDE by mayhem/build.sh: adds the fuzz targets (targets.cmake) once
# upstream's top-level CMakeLists.txt has finished defining libgerbera — no upstream file is edited.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    cmake_language(DEFER DIRECTORY ${CMAKE_SOURCE_DIR} CALL include "${CMAKE_SOURCE_DIR}/mayhem/fuzz/targets.cmake")
endif()
