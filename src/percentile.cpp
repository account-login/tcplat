// system
#include <sys/time.h>
// proj
#include "percentile.h"


namespace tcplat {

    const char *const k_percentile_desc[] = {
        "  1us",
        "  2us",
        "  4us",
        "  8us",
        " 16us",
        " 32us",
        " 64us",
        "128us",
        "256us",
        "512us",
        "  1ms",
        "  2ms",
        "  4ms",
        "  8ms",
        " 16ms",
        " 33ms",
        " 65ms",
        "131ms",
        "262ms",
        "524ms",
        "   1s",
        " 2.1s",
        " 4.2s",
        " 8.4s",
        NULL,
    };

    Percentile::Percentile() {
        memset(this, 0, sizeof(*this));

        // seed with time
        union {
            unsigned short int seed16v[3];
            uint64_t u64;
        } u;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        u.u64 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
        seed48_r(u.seed16v, &this->rand);
    }

    void Percentile::feed(const Sample &sample) {
        size_t idx = 0;
        uint64_t lat = sample.lat;
        if (lat > 0) {
            idx = (8 * sizeof(unsigned long long)) - __builtin_clzll(lat);      // log2(lat) + 1
        }
        if (idx >= k_percentile_bin_cnt) {
            idx = k_percentile_bin_cnt - 1;
        }

        this->bins[idx]++;
        this->total++;

        double r = 0;
        drand48_r(&this->rand, &r);
        if (r < 1.0 / this->bins[idx]) {
            this->samples[idx] = sample;
        }
    }

    void Percentile::reset() {
        struct drand48_data save = this->rand;
        memset(this, 0, sizeof(*this));
        this->rand = save;
    }

}   // ::tcplat
