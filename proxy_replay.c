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

#include <libpcap.h>

#include "hashmap.h"

#define NO_PAYLOAD_MAX_PKT_SIZE 100
#define MAX_IFACE_LEN 32
#define MAX_PATH_LEN 1024
#define MAX_FILTER_LEN 1024

struct tuple {
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint16_t src_port;
    uint16_t dst_port;
};
struct maps {
    struct tuple original_tuple;
    struct tuple proxy_tuple;
    uint32_t flags;
    unsigned char buffers[3][NO_PAYLOAD_MAX_PKT_SIZE];
};

struct options {
    char read_file[MAX_PATH_LEN];
    char write_file[MAX_PATH_LEN];
    char read_iface[MAX_IFACE_LEN];
    char write_iface[MAX_IFACE_LEN];
    char filter[MAX_FILTER_LEN];
};
struct options opts;

void read_options(int argc, char* argv[])
{
    int opt;
    memset((void *)&opts, 0, sizeof(opts));

    // put ':' at the starting of the string so compiler can distinguish between '?' and ':'
    while((opt = getopt(argc, argv, ":r:w:i:o:h")) != -1)
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

        case ':':  /* no value supplied */
            printf("option %c requires a value\n", optopt);
            exit(-1);

        case '?':  /* unknown option */
        default:
            printf("option %c not recognized\n", optopt);
            exit(-1);
        }
    }

    if(strlen(opts.read_file) > 0 && strlen(opts.read_iface) > 0)
    {
        printf("Cannot read from both file and interface\n");
        assert(0);
    }
    if(strlen(opts.write_file) > 0 && strlen(opts.write_iface) > 0)
    {
        printf("Cannot write to both file and interface\n");
        assert(0);
    }

    if(optind < argc)
    {
        printf("bpf filter: ");
        for(; optind < argc; optind++)
        {
            printf("%s ", argv[optind]);
        }
        printf("\n");
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

int main(int argc, char* argv[], char* env[])
{
    read_options(argc, argv);

    /* open pkt_src */
    /* open pkt_dst */

    /* while(read_pkt(pkt_src)) */
    {
        /* tuple_hash = hash_pkt_tuple(pkt); */
        /* if (map = lookup_map(tuple_hash)) == NULL */
        {
            /* if RST in pkt.flags or ACK == pkt.flags */
                /* log_weird(pkt) */
            /* else */
                /* create_map(pkt) */
        }

        /* not a simple else clause as map may have been created above */
        /* if (map = lookup_map(tuple_hash)) != NULL */
        {
            /* if SYN in src.flags */
                /* map.flags.srcsyn = 1; */
            /* if SYN in dst.flags */
                /* map.flags.dstsyn = 1; */

            /* if not map.proxy && pkt.payload_len > 0 */
                /* populate_proxy(pkt, map) */

            /* if map.proxy */
                /* update_and_replay_pkt(pkt, map, pkt_dst) */
            /* else */
            {
                /* if pkt.payload_len > 0 || map.num_buffered >= 3 */
                    /* log_weird(pkt) */
                /* else */
                    /* buffer_pkt(pkt, map) */
            }

            /* if RST in pkt.flags || map.flags.srcfin && map.flags.dstfin */
                /* rm_map(tuple_hash) */
            /* else */
            {
                /* if FIN in src.flags */
                    /* map.flags.srcfin = 1; */
                /* if FIN in dst.flags */
                    /* map.flags.dstfin = 1; */
            }
        }
        /* else */
            /* log_weird(pkt) */
    }

    /* close(pkg_src); */
    /* close(pkg_dst); */

    return 0;
}
