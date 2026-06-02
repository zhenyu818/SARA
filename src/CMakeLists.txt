# gpgpusim_entrypoint objects
add_library(gpgpusim_entrypoint OBJECT
    abstract_hardware_model.cc
    debug.cc
    gpgpusim_entrypoint.cc
    option_parser.cc
    statwrapper.cc
    stream_manager.cc
    trace.cc)

add_library(exact_storage_backend SHARED
    analysis/ptx_influence.cc
    analysis/ptx_influence_capi.cc)

add_executable(exact_storage_core
    analysis/exact_storage_main.cc
    analysis/ptx_influence.cc)

add_executable(exact_core
    analysis/exact_core_main.cc
    analysis/ptx_influence.cc)

# Add current folder and CUDA include to include path
target_include_directories(gpgpusim_entrypoint PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(gpgpusim_entrypoint PUBLIC ${CUDAToolkit_INCLUDE_DIRS})
target_include_directories(exact_storage_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(exact_storage_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(exact_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(exact_core PUBLIC ${PROJECT_SOURCE_DIR}/third_party)

set_target_properties(exact_storage_backend PROPERTIES
    OUTPUT_NAME exact_storage_backend
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/tools/native)
set_target_properties(exact_storage_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/tools/native)
set_target_properties(exact_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/tools/native)

# Add subdir
add_subdirectory(accelwattch)
add_subdirectory(cuda-sim)
add_subdirectory(gpgpu-sim)
add_subdirectory(intersim2)
