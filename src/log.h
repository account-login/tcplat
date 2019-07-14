#pragma once

namespace tcplat {

    void log(const char *fmt, ...);

#define LOG_ERR(fmt, ...)  log("[ERROR] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log("[INFO]  " fmt, ##__VA_ARGS__)

}
