#ifdef USE_EMSCRIPTEN
#include <emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

extern "C" {
    void leak_check();
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
namespace __lsan {
    void DoLeakCheck();
}
#endif
#endif

EMSCRIPTEN_KEEPALIVE
void leak_check() {
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#ifdef USE_EMSCRIPTEN
  // code for ASan-enabled builds
  __lsan::DoLeakCheck();
    // lsan_do_leak_check();
#endif
#endif
#endif
}
