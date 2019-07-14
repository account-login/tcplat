#pragma once

// system
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


namespace tcplat {

    const size_t k_percentile_bin_cnt = 24;
    extern const char *const k_percentile_desc[];
    const size_t k_percentile_max_sample_req_size = 1024;

    struct Sample {
        uint64_t    lat;
        uint64_t    ts;
        size_t      req_size;
        size_t      sample_size;
        uint8_t     sample_data[k_percentile_max_sample_req_size];
    };

    struct Percentile {
        size_t bins[k_percentile_bin_cnt];
        Sample samples[k_percentile_bin_cnt];
        size_t total;

        struct drand48_data rand;

        Percentile();
        void feed(const Sample &sample);
        void reset();
    };

}   // ::tcplat
