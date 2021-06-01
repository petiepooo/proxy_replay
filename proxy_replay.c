/* proxy_replay.c
 *
 * A bridge for rewriting sniffed PROXY Protocol packets as how they would look before the proxy
 *
 * Copyright 2021 Peter Nelson, all rights reserved.
 * Use of this source code is governed by an MIT-style
 * license that can be found in accompaning LICENSE file.
 *
 *
 */

#include <stdlib.h> 
#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <assert.h>

#include <pcap.h>

#include "hashmap.h"

#define NO_PAYLOAD_MAX_IPV4_PKT_SIZE 100 /* TODO: seeing most are 54? */
#define IPV4_PCAP_HDR_SIZE 32 /* TODO: better size?  */
#define MAX_IFACE_LEN 32
#define MAX_PATH_LEN 1024
#define MAX_FILTER_LEN 1024


#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10

struct ipv4_tuple {
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint16_t src_port;
    uint16_t dst_port;
};

struct ipv4_maps {
    struct ipv4_tuple original_tuple;
    struct ipv4_tuple proxy_tuple;
    uint32_t flags;
    unsigned char header[3][IPV4_PCAP_HDR_SIZE];
    unsigned char buffers[3][NO_PAYLOAD_MAX_IPV4_PKT_SIZE];
};

struct options {
    char read_file[MAX_PATH_LEN];
    char write_file[MAX_PATH_LEN];
    char read_iface[MAX_IFACE_LEN];
    char write_iface[MAX_IFACE_LEN];
    char filter[MAX_FILTER_LEN];
    int debug;
};
struct options opts;

void read_options(int argc, char* argv[])
{
    int opt;

    // put ':' at the starting of the string so compiler can distinguish between '?' and ':'
    while((opt = getopt(argc, argv, ":r:w:i:o:hd")) != -1)
    {
        switch(opt)
        {
        case 'r':  /* read pcap file */
            assert(strlen(optarg) < MAX_PATH_LEN);
            strncpy(opts.read_file, optarg, MAX_PATH_LEN);
            break;

        case 'w':  /* write pcap file */
            assert(strlen(optarg) < MAX_PATH_LEN);
            strncpy(opts.write_file, optarg, MAX_PATH_LEN);
            break;

        case 'i':  /* read from iface */
            assert(strlen(optarg) < MAX_IFACE_LEN);
            strncpy(opts.read_iface, optarg, MAX_IFACE_LEN);
            break;

        case 'o':  /* write to iface */
            assert(strlen(optarg) < MAX_IFACE_LEN);
            strncpy(opts.write_iface, optarg, MAX_IFACE_LEN);
            break;

        case 'h':  /* display help */
            printf("todo: display help\n");
            exit(0);

        case 'd':  /* debug mode */
            opts.debug = 1;
            break;

        case ':':  /* no value supplied */
            fprintf(stderr, "option %c requires a value\n", optopt);
            exit(-1);

        case '?':  /* unknown option */
        default:
            fprintf(stderr, "option %c not recognized\n", optopt);
            exit(-1);
        }
    }

    for(int len=0; optind < argc; optind++)
    {
        len += snprintf(opts.filter+len, MAX_FILTER_LEN-len, "%s", argv[optind]);
        len += snprintf(opts.filter+len, MAX_FILTER_LEN-len, " ");
        /* TODO: warn if truncated (silently fails now) */
    }

    if(strlen(opts.read_file) == 0 && strlen(opts.read_iface) == 0)
        strncpy(opts.read_iface, "en0", MAX_IFACE_LEN);
    else if(strlen(opts.read_file) > 0 && strlen(opts.read_iface) > 0)
    {
        fprintf(stderr, "Cannot read from both file and interface\n");
        assert(0);
    }
    if(strlen(opts.write_file) == 0 && strlen(opts.write_iface) == 0)
        opts.debug = 1;
    else if(strlen(opts.write_file) > 0 && strlen(opts.write_iface) > 0)
    {
        fprintf(stderr, "Cannot write to both file and interface\n");
        assert(0);
    }

    if(opts.debug)
    {
        fprintf(stderr, "debug mode enabled\n");
        if(strlen(opts.filter))
            fprintf(stderr, "filter: %s\n", opts.filter);
    }
}

void update_and_replay_pkt(pkt, map, pkt_dst)
{
    /* while(map.num_buffered > 0) */
    {
        /* adjust_buffer_seq(map.buffer[0], map.seq_offset) */
        /* update_packet(map, map.buffer[0]) */
        /* replay_packet(map.buffer[0]) */
        /* unbuffer_pkt(map) */
    }
    /* update_packet(map, pkt) */
    /* replay_packet(pkt) */
}

void hash_pkt_tuple(const u_char* pkt, struct ipv4_tuple* tuple)
{
    uint32_t src_ipv4 = 0;
    uint32_t dst_ipv4 = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    memset(tuple, 0, sizeof(struct ipv4_tuple));
    /* extract IPs and ports */

    if(src_ipv4 < dst_ipv4)
    {
        tuple->src_ipv4 = src_ipv4;
        tuple->dst_ipv4 = dst_ipv4;
    }
    else
    {
        tuple->src_ipv4 = dst_ipv4;
        tuple->dst_ipv4 = src_ipv4;
    }
    if(src_port < dst_port)
    {
        tuple->src_port = src_port;
        tuple->dst_port = dst_port;
    }
    else
    {
        tuple->src_port = dst_port;
        tuple->dst_port = src_port;
    }
}

u_char extract_flags_if_tcp(const u_char* pkt)
{
    /* if not tcp */
        return 0;
    /* return tcp flag field */
}

int main(int argc, char* argv[], char* env[])
{
    uint64_t packet_count = 0;
    pcap_t* in_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* pheader;
    struct bpf_program fp;
    const u_char* packet;
    int rc;
    u_char tcp_flags;
    struct ipv4_tuple hashable_tuple;

    read_options(argc, argv);

    if(strlen(opts.read_iface) > 0)
        in_handle = pcap_open_live(opts.read_iface, 0, 1, 100, errbuf);
    else
        in_handle = pcap_open_offline(opts.read_file, errbuf);
    assert(in_handle != NULL);

    /* open pkt_dst */

    while((rc = pcap_next_ex(in_handle, &pheader, &packet)) == 1 || rc == 0)
    {
        if(rc == 0)
            continue;
        assert(rc);
        ++packet_count;
        if(opts.debug)
            fprintf(stderr, "Jacked a packet with length of [%d]\n", pheader->len);

        hash_pkt_tuple(packet, &hashable_tuple);
        tcp_flags = extract_flags_if_tcp(packet);

        /* if (map = lookup_map(hashable_tuple)) == NULL */
        {
            if(tcp_flags == 0 || (tcp_flags & TH_RST) == 0)
            {
                /* map = create_map(hashable_tuple, packet) */
                if(tcp_flags && (tcp_flags & TH_SYN) == 0)
                {
                    /* map.flags.discard = 1 */
                    /* log(partial) */
                }
            }
        }

        /* if map != NULL */
        {
            /* update_map_ts(); */

            /* if(map.flags.discard) */
                /* continue; */

            /* if(not map.proxy && pkt.payload_len > 0) */
            {
                if(tcp_flags || (tcp_flags & TH_SYN) == TH_SYN)
                {
                    /* populate_proxy(pkt, map) */
                }
                /* else */ /* TODO: handle UDP? */
                {
                    /* map.flags.discard = 1 */
                    /* log(partial stream) */
                }
            }

            /* if map.proxy */
                /* update_and_replay_pkt(pkt, map, pkt_dst) */
            /* else */
            {
                /* if pkt.payload_len == 0 || map.num_buffered < 3 */
                    /* buffer_pkt(pkt, map) */
                /* else maybe log as weird */
            }

            /* if is_tcp(packet) && RST in pkt.flags || map.flags.srcfin && map.flags.dstfin */
                /* rm_map(hashable_tuple) */
        }
        /* else */
            /* log_weird(pkt) */

    if(packet_count % 10 == 0)
        /* check another entry for expiry */
        break; /* TODO: remove when done debugging */
    }

    pcap_close(in_handle);
    /* close(pkg_dst); */

    if(opts.debug)
        fprintf(stderr, "Jacked a total of %llu packets\n", packet_count);
    return 0;
}
