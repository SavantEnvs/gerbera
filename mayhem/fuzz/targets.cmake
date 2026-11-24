# Fuzz targets, included at the end of gerbera's top-level CMakeLists.txt (deferred from
# mayhem/fuzz/project-include.cmake), so the real libgerbera target with all its PUBLIC deps exists.
# One libFuzzer binary + one standalone reproducer per mayhem/fuzz/fuzz_*.cc. CMAKE_C/CXX_FLAGS carry
# $SANITIZER_FLAGS $DEBUG_FLAGS (mayhem/build.sh), so libgerbera itself is instrumented.
set(GRB_SRC ${CMAKE_SOURCE_DIR})
set(FUZZ_DIR ${GRB_SRC}/mayhem/fuzz)
find_package(GTest REQUIRED)   # gmock, for the test/mock Config/Database stand-ins

add_library(fuzz_standalone_main OBJECT $ENV{STANDALONE_FUZZ_MAIN})
set_source_files_properties($ENV{STANDALONE_FUZZ_MAIN} PROPERTIES LANGUAGE C)

separate_arguments(FUZZ_ENGINE UNIX_COMMAND "$ENV{LIB_FUZZING_ENGINE}")

file(GLOB HARNESSES ${FUZZ_DIR}/fuzz_*.cc)
foreach(h ${HARNESSES})
    get_filename_component(name ${h} NAME_WE)
    foreach(kind fuzz standalone)
        if(kind STREQUAL "fuzz")
            set(exe ${name})
        else()
            set(exe ${name}-standalone)
        endif()
        add_executable(${exe} ${h} ${FUZZ_LSAN_OFF_OBJ})   # compiled by mayhem/build.sh
        target_include_directories(${exe} PRIVATE ${GRB_SRC}/src ${GRB_SRC}/test)
        target_link_libraries(${exe} PRIVATE libgerbera GTest::gmock)
        if(kind STREQUAL "fuzz")
            target_link_options(${exe} PRIVATE ${FUZZ_ENGINE})
        else()
            target_sources(${exe} PRIVATE $<TARGET_OBJECTS:fuzz_standalone_main>)
        endif()
    endforeach()
endforeach()
