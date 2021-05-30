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
#include <string.h> 

#include <libpcap.h>

#include "hashmap.h"

#define NO_PAYLOAD_MAX_PKT_SIZE 66

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
};
struct options opts;

void read_options(int argc, char** argv)
{
    memset((void *)&opts, 0, sizeof(opts));
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

int main(int argc, char** argv, char** env)
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
