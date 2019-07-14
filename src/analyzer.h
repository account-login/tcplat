#pragma once

// system
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <utility>
#include <vector>
#include <map>
// proj
#include "percentile.h"


namespace tcplat {

    struct Packet {
        uint32_t dst_ip;
        uint16_t dst_port;

        uint32_t src_ip;
        uint16_t src_port;

        struct timeval ts;
        size_t payload_size;
        uint8_t *payload_data;

        // TODO: constructor
    };

    struct SessionState {
        bool req;
        Sample current_sample_req;

        SessionState()
            : req(false)
        {}
    };

    typedef std::pair<uint32_t, uint16_t> SessionKey;   // client ip port
    typedef std::map<SessionKey, SessionState> SessionMap;

    struct Analyzer {
        // param
        uint32_t server_ip;
        uint16_t server_port;

        Analyzer() : server_ip(0), server_port(0) {}

        void feed(const Packet &p);

        // state
        SessionMap sessions;
        Percentile percentile;
    };

}   // ::tcplat
