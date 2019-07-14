// system
#include <string.h>
// proj
#include "analyzer.h"
#include "log.h"

namespace tcplat {

    static uint64_t timeval2us(timeval tv) {
        return uint64_t(tv.tv_sec) * 1000000 + tv.tv_usec;
    }

    static void req(Analyzer &an, const Packet &p, SessionState &s) {
        Sample &sa = s.current_sample_req;

        if (s.req) {
            sa.req_size += p.payload_size;
            return;
        }

        s.req = true;
        sa.req_size = p.payload_size;
        sa.ts = timeval2us(p.ts);
        sa.sample_size = p.payload_size;
        if (sa.sample_size > k_percentile_max_sample_req_size) {
            sa.sample_size = k_percentile_max_sample_req_size;
        }
        memcpy(sa.sample_data, p.payload_data, sa.sample_size);
    }

    static void res(Analyzer &an, const Packet &p, SessionState &s) {
        if (!s.req) {
            return;
        }

        Sample &sa = s.current_sample_req;

        s.req = false;
        sa.lat = timeval2us(p.ts) - sa.ts;
        // bad case: p.ts < sa.ts or sa.ts == 0
        if (sa.lat >= 100 * 1000 * 1000) {
            return;     // lat >= 100s
        }

        an.percentile.feed(sa);
    }

    void Analyzer::feed(const Packet &p) {
        if (p.payload_size == 0) {
            return;     // no tcp data
        }

        // server to client
        if (p.src_ip == this->server_ip && p.src_port == this->server_port) {
            res(*this, p, this->sessions[SessionKey(p.dst_ip, p.dst_port)]);
        }
        // client to server
        else if (p.dst_ip == this->server_ip && p.dst_port == this->server_port) {
            req(*this, p, this->sessions[SessionKey(p.src_ip, p.src_port)]);
        }
        // else drop
    }

}   // ::tcplat
