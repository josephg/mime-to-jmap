cmake_minimum_required(VERSION 3.10)
project(mimer VERSION 1.0.0 LANGUAGES C)

file(GLOB SOURCES src/*.c)
file(GLOB JANSSON_SOURCES jansson/*.c)

link_directories(/usr/local/opt/icu4c/lib /usr/local/lib)
#link_directories(/Users/josephg/3rdparty/icu/icu4c/source/lib /usr/local/lib)

add_executable(mimer ${SOURCES} ${JANSSON_SOURCES})
#add_subdirectory(src)


#include(CMakeFindDependencyMacro)
#find_dependency(jansson REQUIRED CONFIG)

target_include_directories(mimer PRIVATE
#  src jansson /Users/josephg/3rdparty/icu/icu4c/source/common
  src jansson /usr/local/opt/icu4c/include
)

set(OPT "SHELL:-flto -O2 -s WASM_OBJECT_FILES=0 --llvm-lto 1")

set(WASM_CFLAGS "SHELL: -s USE_PTHREADS=1 -DUSE_EMSCRIPTEN")
set(WASM_LDFLAGS "SHELL:-s TOTAL_MEMORY=50331648 -s EXTRA_EXPORTED_RUNTIME_METHODS='[\"ccall\", \"cwrap\"]'")

#message(${WASM_LDFLAGS})

target_compile_options(mimer PRIVATE
  "-DHAVE_CONFIG_H"
#  ${OPT}
)

target_link_options(mimer PRIVATE
  -fvisibility=hidden
#  ${OPT}
#  ${WASM_LDFLAGS}
)

target_link_libraries(mimer
  icuuc
#  /Users/josephg/3rdparty/icu/icu4c/source/lib/libicuuc.a
#  /Users/josephg/3rdparty/icu/icu4c/source/lib/libicudata.a
)

#find_package(icu4c 64.2 
