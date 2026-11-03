cmake_minimum_required(VERSION 3.20)
project(nemesis.dev_Loader LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/utf-8 /W4 /permissive-)
  set_source_files_properties(src/sqlite3.c PROPERTIES COMPILE_FLAGS "/W0") 
endif()

set(NET_LIBS ws2_32)

add_executable(nemesis.dev WIN32 src/main.cpp src/license_core.cpp)
target_include_directories(nemesis.dev PRIVATE src)
target_link_libraries(nemesis.dev PRIVATE gdiplus dwmapi bcrypt crypt32 user32 gdi32 uxtheme comdlg32 ${NET_LIBS})

add_executable(nemesis.dev.dev WIN32 src/main.cpp src/license_core.cpp)
target_include_directories(nemesis.dev.dev PRIVATE src)
target_compile_definitions(nemesis.dev.dev PRIVATE NEMESIS_DEV_BUILD=1)
target_link_libraries(nemesis.dev.dev PRIVATE gdiplus dwmapi bcrypt crypt32 user32 gdi32 uxtheme comdlg32 ${NET_LIBS})
set_target_properties(nemesis.dev.dev PROPERTIES OUTPUT_NAME "nemesis.dev(DeveloperAccess)")

add_executable(nemesis_server src/server.cpp src/sqlite3.c)
target_include_directories(nemesis_server PRIVATE src)
target_link_libraries(nemesis_server PRIVATE crypt32 advapi32 ${NET_LIBS})