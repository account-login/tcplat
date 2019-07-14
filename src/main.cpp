// systen
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <string>
#include <memory>
// 3rd
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
// proj
#include "log.h"
#include "analyzer.h"
#include "string_util.hpp"


using namespace std;
using namespace tz;
using namespace tcplat;


// output little endian
static bool parse_ipv4(const char *input, uint32_t &ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    int rv = inet_pton(AF_INET, input, buf);
    if (rv != 1) {
        return false;
    }

    struct in_addr *inaddr = (struct in_addr *)&buf;
    ip = ntohl(inaddr->s_addr);
    return true;
}

struct Argument {
    string server;
    int percentile;
    int sample;
    double delay;

    Argument()
        : percentile(0)
        , sample(0)
        , delay(0)
    {}
};

static Argument get_args(int argc, char *argv[]) {
    Argument arg;

    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    while (true) {
        struct option long_options[] = {
            /* These options don’t set a flag.
                We distinguish them by their indices. */
            {"server",  required_argument, 0, 's'},
            {"percentile", no_argument, 0, 'p'},
            {"sample", no_argument, 0, 'S'},
            {"delay", required_argument, 0, 'd'},
            {0, 0, 0, 0}
        };

        /* getopt_long stores the option index here. */
        int option_index = 0;
        int c = getopt_long(argc, argv, "s:pSd:", long_options, &option_index);
        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 'p':
            arg.percentile = 1;
            break;
        case 'S':
            arg.sample = 1;
            break;
        case 's':
            arg.server = optarg;
            break;
        case 'd':
            arg.delay = atof(optarg);
            break;
        case '?':
            /* getopt_long already printed an error message. */
        default:
            // TODO: help
            ;
        }

        /* Print any remaining command line arguments (not options). */
        // while (optind < argc) {
        //     printf ("%s ", argv[optind++]);
        // }
    }

    return arg;
}

static uint64_t timeval2us(timeval tv) {
    return uint64_t(tv.tv_sec) * 1000000 + tv.tv_usec;
}

static void output(const Argument &arg, const Analyzer &an);

static void process(const Argument &arg, Analyzer &an, pcpp::IFileReaderDevice &reader) {
    uint64_t start_ts = 0;

    pcpp::RawPacket packet;
    while (reader.getNextPacket(packet)) {
        // parse the raw packet into a parsed packet
        pcpp::Packet parsed(&packet);

        // ipv4 layer
        pcpp::IPv4Layer* ip_layer = parsed.getLayerOfType<pcpp::IPv4Layer>();
        if (!ip_layer) {
            continue;
        }
        // tcp layer
        pcpp::TcpLayer* tcp_layer = parsed.getLayerOfType<pcpp::TcpLayer>();
        if (!tcp_layer) {
            continue;
        }

        Packet p;
        p.src_ip = ntohl(ip_layer->getIPv4Header()->ipSrc);
        p.src_port = ntohs(tcp_layer->getTcpHeader()->portSrc);
        p.dst_ip = ntohl(ip_layer->getIPv4Header()->ipDst);
        p.dst_port = ntohs(tcp_layer->getTcpHeader()->portDst);
        p.ts = packet.getPacketTimeStamp();
        p.payload_size = tcp_layer->getLayerPayloadSize();
        p.payload_data = tcp_layer->getLayerPayload();

        uint64_t cur_ts = timeval2us(p.ts);
        if (start_ts == 0) {
            start_ts = cur_ts;
        }

        if (arg.delay > 0 && start_ts + uint64_t(arg.delay * 1e6) < cur_ts) {
            output(arg, an);
            // reset
            start_ts = cur_ts;
            an.percentile.reset();
        }

        an.feed(p);
    }

    // last interval
    if (an.percentile.total > 0) {
        output(arg, an);
    }
}

static string print_ascii(const char *data, size_t size, size_t limit) {
    string s;
    for (size_t i = 0; i < size && i < limit; ++i) {
        if (isprint(data[i])) {
            s.push_back(data[i]);
        } else {
            s.push_back('.');
        }
    }
    return s;
}

static string lpad(const string &input, size_t len) {
    if (input.size() >= len) {
        return input;
    } else {
        return string(len - input.size(), ' ') + input;
    }
}

static void fmt_table(const vector<vector<string> > &rows, vector<string> &out) {
    assert(rows.size() > 0);
    out.clear();

    size_t ncol = rows[0].size();
    vector<size_t> width(ncol);
    for (size_t i = 0; i < rows.size(); ++i) {
        const vector<string> &r = rows[i];
        assert(r.size() == ncol);
        for (size_t j = 0; j < ncol; ++j) {
            width[j] = std::max(width[j], r[j].size());
        }
    }

    for (size_t i = 0; i < rows.size(); ++i) {
        const vector<string> &r = rows[i];
        out.push_back(string());
        string &line = out.back();
        for (size_t j = 0; j < ncol; ++j) {
            line += lpad(r[j], 1 + width[j]);
        }
    }
}

static int get_win_size(struct winsize *ws) {
    return ioctl(STDOUT_FILENO, TIOCGWINSZ, ws);
}

static void print_percentile(const Argument &arg, const Analyzer &an) {
    // print bins
    size_t first_idx = 0;
    while (first_idx < k_percentile_bin_cnt - 1 && an.percentile.bins[first_idx + 1] == 0) {
        ++first_idx;
    }
    size_t last_idx = k_percentile_bin_cnt - 1;
    while (last_idx > 0 && an.percentile.bins[last_idx] == 0) {
        --last_idx;
    }

    vector<vector<string> > table;
    table.push_back(vector<string>());
    table.back().push_back("bins");
    table.back().push_back("count");
    table.back().push_back("percentage");
    table.back().push_back("accumulated");

    size_t acc = 0;
    for (size_t i = first_idx; i <= last_idx; ++i) {
        size_t cnt = an.percentile.bins[i];
        size_t total = an.percentile.total;
        acc += cnt;

        table.push_back(vector<string>());
        table.back().push_back(k_percentile_desc[i]);
        table.back().push_back(str(cnt));
        table.back().push_back(strfmt("%.1f %%", 100.0 * cnt / total));
        table.back().push_back(strfmt("%.1f %%", 100.0 * acc / total));
    }

    size_t term_width = 0;
    if (arg.sample) {
        struct winsize ws = {};
        if (get_win_size(&ws) == 0) {
            term_width = ws.ws_col;
        }
    }

    vector<string> lines;
    fmt_table(table, lines);
    for (size_t i = 0; i < lines.size(); ++i) {
        string &line = lines[i];
        if (arg.sample && i != 0) {
            const Sample &sa = an.percentile.samples[first_idx + i - 1];
            if (sa.req_size > 0 && term_width > line.size() + 2) {
                size_t sample_limit = term_width - (line.size() + 2);
                line += " |" + print_ascii((const char *)sa.sample_data, sa.sample_size, sample_limit);
            }
        }
        fputs(line.c_str(), stdout);
        fputc('\n', stdout);
    }
}

static void output(const Argument &arg, const Analyzer &an) {
    LOG_INFO("total: %zu", an.percentile.total);
    if (arg.percentile) {
        print_percentile(arg, an);
    }
}

int main(int argc, char* argv[]) {
    // parse args
    Argument arg = get_args(argc, argv);

    // setup analyzer
    size_t i = arg.server.rfind(":");
    if (i == string::npos) {
        LOG_ERR("--server ip:port required");
        return 1;
    }
    string ip_s = arg.server.substr(0, i);
    string port_s = arg.server.substr(i + 1);

    Analyzer an;
    if (!parse_ipv4(ip_s.c_str(), an.server_ip)) {
        LOG_ERR("bad ip address");
        return 1;
    }
    an.server_port = atol(port_s.c_str());
    if (an.server_port == 0) {
        LOG_ERR("bad port number");
        return 1;
    }

    // open device
    const std::auto_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("-"));
    assert(reader.get() != NULL);
    if (!reader->open()) {
        LOG_ERR("Cannot open stdin for reading");
        return 1;
    }

    // analyze packets
    process(arg, an, *reader.get());

    // close the file reader, we don't need it anymore
    reader->close();

    return 0;
}
