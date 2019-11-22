#include "config.h"
#include <assert.h>
#include <stdio.h>

int main() {
    printf("oh hai\n");
    return 0;
}


EXPORTED void fatal(const char *s, int code) {
    assert(0);
}