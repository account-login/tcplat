// system
#include <stdarg.h>
#include <stdio.h>
// proj
#include "log.h"

namespace tcplat {

    void log(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        (void)vfprintf(stderr, fmt, ap);
        va_end(ap);
        (void)fprintf(stderr, "\n");
    }

}
