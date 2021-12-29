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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "hashmap.h"

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;	/* sequence number */
    tcp_seq th_ack;	/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;	/* window */
    u_short th_sum;	/* checksum */
    u_short th_urp;	/* urgent pointer */
};

struct sniff_udp {
    u_short uh_sport;	/* source port */
    u_short uh_dport;	/* destination port */
    u_short uh_len;	/* length */
    u_short uh_sum;	/* checksum */
};

#define NO_PAYLOAD_MAX_IPV4_PKT_SIZE 80	/* SYN with 20-byte tcp opts is 74 bytes */
#define MAX_IFACE_LEN 32
#define MAX_PATH_LEN 1024
#define MAX_FILTER_LEN 1024

struct ipv4_tuple {
    struct in_addr src_ipv4;
    struct in_addr dst_ipv4;
    uint16_t src_port;
    uint16_t dst_port;
};

enum pkt_type_e {UNKNOWN, TCP6, TCP4, UDP6, UDP4};

struct ipv4_info {
    enum pkt_type_e pkt_type;
    uint16_t payload_len;
    u_char payload_offset;
    u_char tcp_flags;
};

struct tcp4_pkt {
    struct pcap_pkthdr* pheader;
    u_char packet[NO_PAYLOAD_MAX_IPV4_PKT_SIZE];
};

struct ipv4_conn {
    struct ipv4_tuple sorted_tuple; /* must be first field in struct */
    struct ipv4_tuple orig_tuple;
    struct ipv4_tuple proxy_tuple;
    time_t created;
    time_t last_seen;
    uint32_t stream_flags;
    uint32_t ppv1_len;
#define MF_DISCARD 0x1
#define MF_BYPASS  0x2
#define MF_SRCFIN  0x4
#define MF_DSTFIN  0x8
    struct tcp4_pkt* syn_pkt;
    struct tcp4_pkt* synack_pkt;
    struct tcp4_pkt* ack_pkt;
};

struct ipv6_tuple {
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    uint16_t src_port;
    uint16_t dst_port;
};

struct ipv6_conn {
    /* TODO: finish IPv6 structs */
    struct ipv6_tuple sorted_tuple; /* must be first field in struct */
    struct ipv6_tuple orig_tuple;
    struct ipv6_tuple proxy_tuple;
    time_t created;
    time_t last_seen;
    uint32_t stream_flags;
};

struct options {
    char read_file[MAX_PATH_LEN];
    char write_file[MAX_PATH_LEN];
    char read_iface[MAX_IFACE_LEN];
    char write_iface[MAX_IFACE_LEN];
    char filter[MAX_FILTER_LEN];
    /* bitfield for option flags */
    uint32_t debug : 1;
    uint32_t verbose : 1;
    uint32_t warn : 1;
};
struct options opts;

/*** hashmap helper funcs ***/

uint64_t ipv4_conn_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct ipv4_conn* conn = item;
    return hashmap_sip(&conn->sorted_tuple, sizeof(struct ipv4_tuple), seed0, seed1);
}

int ipv4_conn_compare(const void *a, const void *b, void *udata) {
    const struct ipv4_conn *ua = a;
    const struct ipv4_conn *ub = b;
    return (ub->sorted_tuple.src_ipv4.s_addr - ua->sorted_tuple.src_ipv4.s_addr)
        || (ub->sorted_tuple.src_port - ua->sorted_tuple.src_port)
        || (ub->sorted_tuple.dst_ipv4.s_addr - ua->sorted_tuple.dst_ipv4.s_addr)
        || (ub->sorted_tuple.dst_port - ua->sorted_tuple.dst_port)
        || 0;
}

bool ipv4_conn_iter(const void *item, void *udata) {
    const struct ipv4_conn *conn = item;
    fprintf(stderr, "\tconn: %p\n", conn);
    fprintf(stderr, "\t\tsort_tuple: %08x:%08x:%hu:%hu\n", \
            conn->sorted_tuple.src_ipv4.s_addr, conn->sorted_tuple.dst_ipv4.s_addr, \
            conn->sorted_tuple.src_port, conn->sorted_tuple.dst_port);
    fprintf(stderr, "\t\torig_tuple: %08x:%08x:%hu:%hu\n", \
            conn->orig_tuple.src_ipv4.s_addr, conn->orig_tuple.dst_ipv4.s_addr, \
            conn->orig_tuple.src_port, conn->orig_tuple.dst_port);
    fprintf(stderr, "\t\tproxy_tuple: %08x:%08x:%hu:%hu\n", \
            conn->proxy_tuple.src_ipv4.s_addr, conn->proxy_tuple.dst_ipv4.s_addr, \
            conn->proxy_tuple.src_port, conn->proxy_tuple.dst_port);
    fprintf(stderr, "\t\tcreated: %ld, last_seen: %ld, duration: %ld, age: %ld\n", \
            conn->created, conn->last_seen, conn->last_seen - conn->created, time(NULL) - conn->created);
    fprintf(stderr, "\t\tstream_flags:%s%s%s%s\n", \
            conn->stream_flags & MF_DISCARD ? " MF_DISCARD" : "", \
            conn->stream_flags & MF_BYPASS ? " MF_BYPASS" : "", \
            conn->stream_flags & MF_SRCFIN ? " MF_SRCFIN" : "", \
            conn->stream_flags & MF_DSTFIN ? " MF_DSTFIN" : "");
    return true;
}

uint64_t ipv6_conn_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct ipv6_conn* conn = item;
    return hashmap_sip(&conn->sorted_tuple, sizeof(struct ipv6_tuple), seed0, seed1);
}

int ipv6_conn_compare(const void *a, const void *b, void *udata) {
    const struct ipv6_conn *ua = a;
    const struct ipv6_conn *ub = b;
    return memcmp(ub->sorted_tuple.src_ipv6.s6_addr, ua->sorted_tuple.src_ipv6.s6_addr, sizeof(struct in6_addr))
        || (ub->sorted_tuple.src_port - ua->sorted_tuple.src_port)
        || memcmp(ub->sorted_tuple.dst_ipv6.s6_addr, ua->sorted_tuple.dst_ipv6.s6_addr, sizeof(struct in6_addr))
        || (ub->sorted_tuple.dst_port - ua->sorted_tuple.dst_port)
        || 0;
}

bool ipv6_conn_iter(const void *item, void *udata) {
    const struct ipv6_conn *conn = item;
    char src[50];
    char dst[50];
    fprintf(stderr, "conn: %p\n", conn);
    inet_ntop(AF_INET6, &conn->sorted_tuple.src_ipv6, src, 50);
    inet_ntop(AF_INET6, &conn->sorted_tuple.dst_ipv6, dst, 50);
    fprintf(stderr, "\tsort_tuple: %s:%s:%hu:%hu\n", \
            src, dst, conn->sorted_tuple.src_port, conn->sorted_tuple.dst_port);
    inet_ntop(AF_INET6, &conn->orig_tuple.src_ipv6, src, 50);
    inet_ntop(AF_INET6, &conn->orig_tuple.dst_ipv6, dst, 50);
    fprintf(stderr, "\torig_tuple: %s:%s:%hu:%hu\n", \
            src, dst, conn->orig_tuple.src_port, conn->orig_tuple.dst_port);
    inet_ntop(AF_INET6, &conn->proxy_tuple.src_ipv6, src, 50);
    inet_ntop(AF_INET6, &conn->proxy_tuple.dst_ipv6, dst, 50);
    fprintf(stderr, "\tproxy_tuple: %s:%s:%hu:%hu\n", \
            src, dst, conn->proxy_tuple.src_port, conn->proxy_tuple.dst_port);
    /* TODO: also display created, last_seen, and stream_flags */
    fprintf(stderr, "\t\tcreated: %ld, last_seen: %ld, duration: %ld, age: %ld\n", \
            conn->created, conn->last_seen, conn->last_seen - conn->created, time(NULL) - conn->created);
    fprintf(stderr, "\t\tstream_flags:%s%s%s%s\n", \
            conn->stream_flags & MF_DISCARD ? " MF_DISCARD" : "", \
            conn->stream_flags & MF_BYPASS ? " MF_BYPASS" : "", \
            conn->stream_flags & MF_SRCFIN ? " MF_SRCFIN" : "", \
            conn->stream_flags & MF_DSTFIN ? " MF_DSTFIN" : "");
    return true;
}

/*** end of hashmap helper funcs ***/

void read_options(int argc, char* argv[])
{
    int opt;
    int len;

    // put ':' at the starting of the string so compiler can distinguish between '?' and ':'
    while((opt = getopt(argc, argv, ":r:w:i:o:hdvW")) != -1)
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
            printf("proxy_replay: replays packets received with PROXY protocol as they would look before proxying\n");
            printf("usage: proxy_replay [-h] [-d] -i iface | -r pcap [ -o iface | -w pcap ]\n");
            /* TODO: expanded verbiage on options and their use */
            exit(0);

        case 'd':  /* debug mode */
            opts.debug = 1;
            break;

        case 'v':  /* verbose mode */
            opts.verbose = 1;
            break;

        case 'W':  /* odd-packet warnings */
            opts.warn = 1;
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

    for(len=0; optind < argc; optind++)
    {
        len += snprintf(opts.filter+len, MAX_FILTER_LEN-len, "%s", argv[optind]);
        len += snprintf(opts.filter+len, MAX_FILTER_LEN-len, " ");
        if(len > MAX_FILTER_LEN - 1)
        {
            fprintf(stderr, "proxy_replay: ERROR: filter length %u exceeds maximum of %u\n", len, MAX_FILTER_LEN);
            exit(-1);
        }
    }

    if(strlen(opts.read_file) == 0 && strlen(opts.read_iface) == 0)
        strncpy(opts.read_iface, "en0", MAX_IFACE_LEN);
    else if(strlen(opts.read_file) > 0 && strlen(opts.read_iface) > 0)
    {
        fprintf(stderr, "Cannot read from both file and interface\n");
        exit(-1);
    }
    if(strlen(opts.write_file) == 0 && strlen(opts.write_iface) == 0)
    {
        fprintf(stderr, "no output specified; debug mode enabled\n");
        opts.debug = 1;
    }
    else if(strlen(opts.write_file) > 0 && strlen(opts.write_iface) > 0)
    {
        fprintf(stderr, "Cannot write to both file and interface\n");
        exit(-1);
    }

    if(opts.debug)
    {
        if(opts.verbose)
        {
            if(strlen(opts.filter))
                fprintf(stderr, "filter: %s\n", opts.filter);
            fprintf(stderr, "sizeof ipv4_conn: %ld, ", sizeof(struct ipv4_conn));
            fprintf(stderr, "sizeof tcp4_pkt: %ld\n", sizeof(struct tcp4_pkt));
        }
    }
}

void parse_pkt(const u_char* pkt, struct ipv4_tuple* orig_tuple, struct ipv4_tuple* sorted_tuple, struct ipv4_info* info)
{
    struct sniff_ethernet* ethernet;
    struct sniff_ip* ip;
    struct sniff_tcp* tcp;
    struct sniff_udp* udp;
    u_char *payload;
    short size_ip;
    short size_tcp;
    short size_udp;

    memset(orig_tuple, 0, sizeof(struct ipv4_tuple));
    memset(sorted_tuple, 0, sizeof(struct ipv4_tuple));
    memset(info, 0, sizeof(struct ipv4_info));
    info->pkt_type = UNKNOWN;

    /* extract IPs and ports */
    ethernet = (struct sniff_ethernet*)(pkt);
    if(opts.debug && opts.verbose) {
        fprintf(stderr, "pkt:ether_type:0x%04hx:", ntohs(ethernet->ether_type));
    }
    if(ntohs(ethernet->ether_type) != 2048)
    {
        fprintf(stderr, "not-ip\n");
        return;
    }
    ip = (struct sniff_ip*)(pkt + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(opts.debug && opts.verbose) {
        fprintf(stderr, "ip-len:%hu:", size_ip);
        fprintf(stderr, "proto:%u:", ip->ip_p);
        fprintf(stderr, "ver:%u:", (ip->ip_vhl)>>4);
    }
    if (size_ip < 20 || size_ip > 1600) {
        fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    if(ip->ip_p == 6) /* TCP */
    {
        tcp = (struct sniff_tcp*)(pkt + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20 || size_tcp > 1600) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        info->pkt_type = TCP4;
        info->payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;
        info->payload_offset = SIZE_ETHERNET + size_ip + size_tcp;
        info->tcp_flags = tcp->th_flags;
   
        orig_tuple->src_ipv4.s_addr = ip->ip_src.s_addr, orig_tuple->dst_ipv4.s_addr = ip->ip_dst.s_addr;
        orig_tuple->src_port = ntohs(tcp->th_sport), orig_tuple->dst_port = ntohs(tcp->th_dport);

        if(opts.debug && opts.verbose) {
            fprintf(stderr, "tcp-len:%hu:", size_tcp);
            fprintf(stderr, "flags:0x%x:", info->tcp_flags);
            fprintf(stderr, "data-start:%u:", info->payload_offset);
            fprintf(stderr, "len:%u\n", info->payload_len);
        }
    }
    else if(ip->ip_p == 17) /* UDP */
    {
        info->pkt_type = TCP4;
        size_udp = 8;
        udp = (struct sniff_udp*)(pkt + SIZE_ETHERNET + size_ip);
        info->payload_len = ntohs(ip->ip_len) - size_ip - size_udp;
        info->payload_offset = SIZE_ETHERNET + size_ip + size_udp;

        orig_tuple->src_ipv4.s_addr = ntohl(ip->ip_src.s_addr), orig_tuple->dst_ipv4.s_addr = ntohl(ip->ip_dst.s_addr);
        orig_tuple->src_port = ntohs(udp->uh_sport), orig_tuple->dst_port = ntohs(udp->uh_dport);

        if(opts.debug && opts.verbose) {
            fprintf(stderr, "udp-len:%hu:", size_udp);
            fprintf(stderr, "data-start:%u:", info->payload_offset);
            fprintf(stderr, "len:%u\n", info->payload_len);
        }
    }
    else
    {
        fprintf(stderr, "not-tcp-or-udp\n");
        return;
    }

    if(orig_tuple->src_ipv4.s_addr < orig_tuple->dst_ipv4.s_addr)
        sorted_tuple->src_ipv4.s_addr = orig_tuple->src_ipv4.s_addr, sorted_tuple->dst_ipv4.s_addr = orig_tuple->dst_ipv4.s_addr;
    else
        sorted_tuple->src_ipv4.s_addr = orig_tuple->dst_ipv4.s_addr, sorted_tuple->dst_ipv4.s_addr = orig_tuple->src_ipv4.s_addr;

    if(orig_tuple->src_port < orig_tuple->dst_port)
        sorted_tuple->src_port = orig_tuple->src_port, sorted_tuple->dst_port = orig_tuple->dst_port;
    else
        sorted_tuple->src_port = orig_tuple->dst_port, sorted_tuple->dst_port = orig_tuple->src_port;

    /*if(opts.debug && opts.verbose) {
        fprintf(stderr, "internal structs: info: %u:%u:%u\n", \
                info->pkt_type, info->payload_len, info->tcp_flags);
        fprintf(stderr, "\t\t  orig_tuple: %08x:%08x:%hu:%hu\n", \
                orig_tuple->src_ipv4, orig_tuple->dst_ipv4, \
                orig_tuple->src_port, orig_tuple->dst_port);
        fprintf(stderr, "\t\t  sort_tuple: %08x:%08x:%hu:%hu\n", \
                sorted_tuple->src_ipv4, sorted_tuple->dst_ipv4, \
                sorted_tuple->src_port, sorted_tuple->dst_port);
    }*/

}

struct ipv4_conn* create_populate_map(struct hashmap* ipv4_hashmap, struct ipv4_tuple* orig_tuple, struct ipv4_tuple* sorted_tuple)
{
    struct ipv4_conn conn;
    struct ipv4_conn* hash = NULL;

    memset(&conn, 0, sizeof(struct ipv4_conn));
    memcpy(&(conn.sorted_tuple), sorted_tuple, sizeof(struct ipv4_tuple));
    memcpy(&(conn.orig_tuple), orig_tuple, sizeof(struct ipv4_tuple));
    conn.created = time(NULL);
    conn.last_seen = time(NULL);
    hashmap_set(ipv4_hashmap, &conn);
    hash = hashmap_get(ipv4_hashmap, &conn);
    assert(hash != NULL);
    return hash;
}

struct ipv4_conn* find_map(struct hashmap* ipv4_hashmap, struct ipv4_tuple* sorted_tuple)
{
    struct ipv4_conn conn;
    struct ipv4_conn* hash = NULL;

    memset(&conn, 0, sizeof(struct ipv4_conn));
    memcpy(&conn.sorted_tuple, sorted_tuple, sizeof(struct ipv4_tuple));
    return hashmap_get(ipv4_hashmap, &conn);
}

void delete_map(struct hashmap* ipv4_hashmap, struct ipv4_conn* conn)
{
    if(conn->syn_pkt)
        free(conn->syn_pkt);
    if(conn->synack_pkt)
        free(conn->synack_pkt);
    if(conn->ack_pkt)
        free(conn->ack_pkt);
    hashmap_delete(ipv4_hashmap, conn);
}

#define MIN(a,b) (((a)<(b))?(a):(b))

void populate_tcp4_proxyv1(struct ipv4_conn* conn, struct pcap_pkthdr* pheader, const u_char* packet, struct ipv4_info* info)
{
    char proxy_str[NO_PAYLOAD_MAX_IPV4_PKT_SIZE];
    const u_char *payload = packet + info->payload_offset;
    char *cursor;
    char *match;
    int len;
    char *src_ip, *dst_ip, *src_port, *dst_port;
    struct ipv4_tuple tuple;
    const char match_v1_str[] = "PROXY TCP4 ";

    memset(proxy_str, 0, NO_PAYLOAD_MAX_IPV4_PKT_SIZE);
    strncpy(proxy_str, (const char *)packet + info->payload_offset, info->payload_len);
    len = info->payload_len;
    if(opts.debug)
        fprintf(stderr, "parsing: %s", proxy_str);

    conn->ppv1_len = len;
    cursor = proxy_str + sizeof(match_v1_str)-1;
    len = strnlen(cursor, NO_PAYLOAD_MAX_IPV4_PKT_SIZE - sizeof(match_v1_str) - 1);
    match = memchr(cursor, ' ', MIN(len, 16));
    if(match && *match == ' ') {
        *match = '\0';
        src_ip = cursor;
        len -= match - cursor + 1;
        cursor = match + 1;
    }
    match = memchr(cursor, ' ', MIN(len, 16));
    if(match && *match == ' ') {
        *match = '\0';
        dst_ip = cursor;
        len -= match - cursor + 1;
        cursor = match + 1;
    }
    match = memchr(cursor, ' ', MIN(len, 6));
    if(match && *match == ' ') {
        *match = '\0';
        src_port = cursor;
        len -= match - cursor + 1;
        cursor = match + 1;
    }
    match = memchr(cursor, '\r', MIN(len, 6));
    if(match && *match == '\r') {
        *match = '\0';
        dst_port = cursor;
        len -= match - cursor + 1;
    }
    if(len != 1 || *(match+1) != '\n')
    {
        if(opts.debug)
            fprintf(stderr, "v1 payload string not formatted correctly; setting to bypass\n");
        conn->stream_flags |= MF_BYPASS;
        return;
    }
    if((inet_aton(dst_ip, &tuple.dst_ipv4) == 0) || (inet_aton(src_ip, &tuple.src_ipv4) == 0))
    {
        if(opts.debug)
            fprintf(stderr, "error converting IP addresses; setting to bypass\n");
        conn->stream_flags |= MF_BYPASS;
        return;
    }
    conn->proxy_tuple.dst_ipv4.s_addr = ntohl(tuple.dst_ipv4.s_addr);
    conn->proxy_tuple.src_ipv4.s_addr = ntohl(tuple.src_ipv4.s_addr);
    conn->proxy_tuple.dst_port = atoi(dst_port);
    conn->proxy_tuple.src_port = atoi(src_port);
    if(opts.debug)
    {
        fprintf(stderr, "map: %p ", conn);
        fprintf(stderr, "proxy_tuple set to %08x:%08x:%hu:%hu\n", \
                conn->proxy_tuple.src_ipv4.s_addr, conn->proxy_tuple.dst_ipv4.s_addr, \
                conn->proxy_tuple.src_port, conn->proxy_tuple.dst_port);
    }
}

void populate_proxy(struct ipv4_conn* conn, struct pcap_pkthdr* pheader, const u_char* packet, struct ipv4_info* info)
{
    const char match_v1_str[] = "PROXY TCP4 ";
    const char match_v2_str[] = "\r\n\r\n\x00\r\nQUIT\n\x21\x11";

    if(info->payload_len >= NO_PAYLOAD_MAX_IPV4_PKT_SIZE)
    {
        if(opts.debug)
            fprintf(stderr, "payload string too long for protocol; setting to bypass\n");
        conn->stream_flags |= MF_BYPASS;
        return;
    }

    if(strncmp((const char *)packet + info->payload_offset, \
               match_v2_str, sizeof(match_v2_str)-1) == 0)
    {
        if(opts.debug)
            fprintf(stderr, "payload string is a v2 match! bypassing for now...\n");
        conn->stream_flags |= MF_BYPASS;
    }

    else if(strncmp((const char *)packet + info->payload_offset, \
               match_v1_str, sizeof(match_v1_str)-1) == 0)
        populate_tcp4_proxyv1(conn, pheader, packet, info);

    else
    {
        if(opts.debug)
            fprintf(stderr, "payload string not a match; setting to bypass\n");
        conn->stream_flags |= MF_BYPASS;
    }
}

void save_tcp4_handshake(struct ipv4_conn* conn, struct pcap_pkthdr* pheader, const u_char* packet, struct ipv4_info* info)
{
    struct tcp4_pkt* dest_buffer = NULL;

    assert(pheader->len < NO_PAYLOAD_MAX_IPV4_PKT_SIZE);

    switch(info->tcp_flags)
    {
    case TH_SYN:
        dest_buffer = conn->syn_pkt;
        break;
    case (TH_SYN | TH_ACK):
        dest_buffer = conn->synack_pkt;
        break;
    case TH_ACK:
        dest_buffer = conn->ack_pkt;
        break;
    default:
        /* log weird */
        return;
    }

    if(dest_buffer)
    {
        dest_buffer = calloc(1, NO_PAYLOAD_MAX_IPV4_PKT_SIZE);
        assert(dest_buffer);
        memcpy(&dest_buffer->pheader, pheader, sizeof(struct pcap_pkthdr));
        memcpy(&dest_buffer->packet, packet, pheader->len);
    }
}

void write_tcp4_handshake(struct ipv4_conn* conn, pcap_dumper_t* dumper, pcap_t* injecter)
{
    if(dumper == NULL && injecter == NULL)
        return;

    if(conn->syn_pkt)
    {
        /* adjust seq for ppv1 */
        /* adjust packet's IPs/ports */
        /* send it */
        free(conn->syn_pkt);
    }
    if(conn->synack_pkt)
    {
        /* adjust ack for ppv1 */
        /* adjust packet's IPs/ports */
        /* send it */
        free(conn->synack_pkt);
    }
    if(conn->ack_pkt)
    {
        /* adjust seq for ppv1 */
        /* adjust packet's IPs/ports */
        /* send it */
        free(conn->ack_pkt);
    }
}

void update_and_write_pkt(struct ipv4_conn* conn, struct pcap_pkthdr* pheader, const u_char* pkt, pcap_dumper_t* dumper, pcap_t* injecter)
{
    if(dumper == NULL && injecter == NULL)
        return;

    /* adjust packet's IPs/ports */
    /* send it */
}

int main(int argc, char* argv[], char* env[])
{
    uint64_t packet_count;
    pcap_t* in_handle;
    pcap_t* inject_handle;
    pcap_dumper_t* dump_handle;
    char readerrbuf[PCAP_ERRBUF_SIZE];
    char writeerrbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* pheader;
    struct bpf_program fp;
    const u_char* packet;
    int rc;
    struct ipv4_tuple orig_tuple;;
    struct ipv4_tuple sorted_tuple;
    struct ipv4_info ipv4_info;
    struct ipv4_conn* conn;
    struct hashmap *ipv4_hashmap;
    struct hashmap *ipv6_hashmap;

    read_options(argc, argv);

    /* TODO: create SIG_USR1 handler to dump hashmap to debug file */

    if(strlen(opts.read_iface) > 0)
        in_handle = pcap_open_live(opts.read_iface, 0, 1, 100, readerrbuf);
    else
        in_handle = pcap_open_offline(opts.read_file, readerrbuf);
    assert(in_handle != NULL);

    dump_handle = NULL;
    if(strlen(opts.write_file) > 0)
    {
        inject_handle = pcap_open_dead(DLT_EN10MB, 262144);
        dump_handle = pcap_dump_open(inject_handle, opts.write_file);
        pcap_close(inject_handle);
    }
    inject_handle = NULL;
    if(strlen(opts.write_iface) > 0)
        inject_handle = pcap_open_live(opts.write_iface, 0, 1, 100, writeerrbuf);

    if(strlen(opts.filter))
    {
        /* TODO: if filter provided, set pcap filter so nothing matches, drain buffer, then set to provided filter */
    }

    ipv4_hashmap = hashmap_new(sizeof(struct ipv4_conn), 512, 0, 0, 
                               ipv4_conn_hash, ipv4_conn_compare, NULL, NULL);
    ipv6_hashmap = hashmap_new(sizeof(struct ipv6_conn), 512, 0, 0, 
                               ipv6_conn_hash, ipv6_conn_compare, NULL, NULL);

    while((rc = pcap_next_ex(in_handle, &pheader, &packet)) == 1 || rc == 0)
    {
        if(rc == 0)
            continue;
        assert(rc);
        ++packet_count;

        /* TODO: rework to determine IPv4 vs IPv6 vs non-IP, */
        /* then TCP4, TCP6, UDP4, UDP6, or non supported */
        /* makes future support say for SCTP easy to add */

        parse_pkt(packet, &orig_tuple, &sorted_tuple, &ipv4_info);
	switch(ipv4_info.pkt_type)
        {
        case TCP4:
            if ((conn = find_map(ipv4_hashmap, &sorted_tuple)) == NULL)
            {
                if(ipv4_info.tcp_flags == 0 || (ipv4_info.tcp_flags & TH_RST) == 0)
                {
                    conn = create_populate_map(ipv4_hashmap, &orig_tuple, &sorted_tuple);
                    if(opts.debug) {
                        fprintf(stderr, "map: %p (%lu) created for tuple: %08x:%08x:%hu:%hu\n", \
                                conn, \
                                hashmap_count(ipv4_hashmap), \
                                sorted_tuple.src_ipv4.s_addr, \
                                sorted_tuple.dst_ipv4.s_addr, \
                                sorted_tuple.src_port, \
                                sorted_tuple.dst_port);
                    }
                    if(conn && ipv4_info.tcp_flags && (ipv4_info.tcp_flags & TH_SYN) == 0)
                    {
                        conn->stream_flags |= MF_DISCARD;
                        /* log(partial stream) */
                        if(opts.warn)
                            fprintf(stderr, "partial 1\n");
                    }
                }
            }

            if(conn)
            {
                conn->last_seen = time(NULL);
                if(conn->stream_flags & MF_DISCARD)
                {
                    //donothing continue;
                }

                else if(conn->proxy_tuple.dst_ipv4.s_addr == 0 && (conn->stream_flags & MF_BYPASS) == 0)
                {
                    if(ipv4_info.payload_len > 0)
                    {
                        populate_proxy(conn, pheader, packet, &ipv4_info);
                        if(conn->proxy_tuple.dst_ipv4.s_addr > 0 || conn->stream_flags & MF_BYPASS)
                        {
                            write_tcp4_handshake(conn, dump_handle, inject_handle);
                            if(conn->stream_flags & MF_BYPASS)
                                update_and_write_pkt(conn, pheader, packet, dump_handle, inject_handle);
                        }
                    }
                    else
                    {
                        if(ipv4_info.pkt_type == TCP4)
                            save_tcp4_handshake(conn, pheader, packet, &ipv4_info);
                        else /* TODO: handle UDP? */
                        {
                            conn->stream_flags |= MF_DISCARD;
                            /* log(partial stream) */
                            if(opts.warn)
                                fprintf(stderr, "partial 2\n");
                        }
                        continue;
                    }
                }

                else
                {
                    update_and_write_pkt(conn, pheader, packet, dump_handle, inject_handle);
                }

                /* if is_tcp(packet) && RST in pkt.flags || map.flags.srcfin && map.flags.dstfin */
                if(conn && ipv4_info.tcp_flags && ipv4_info.tcp_flags & TH_RST)
                {
                    if(opts.debug)
                        fprintf(stderr, "map: %p deleted on RST\n", conn);
                    delete_map(ipv4_hashmap, conn);
                }
                else if(conn && conn->stream_flags == (MF_SRCFIN | MF_DSTFIN) && ipv4_info.tcp_flags == TH_ACK)
                {
                    if(opts.debug)
                        fprintf(stderr, "map: %p deleted on final ACK\n", conn);
                    delete_map(ipv4_hashmap, conn);
                }
                else if(conn && ipv4_info.tcp_flags & TH_FIN)
                {
                    if(conn->stream_flags & MF_SRCFIN)
                        conn->stream_flags |= MF_DSTFIN;
                    conn->stream_flags |= MF_SRCFIN;
                }

                //if(ipv4_info.
                    /* rm_map(sorted_tuple) */
            }
            /* else */
                /* log_weird(pkt) */

            break;

        /* TODO: handle other packet types */
        case UDP4:
            fprintf(stderr, "sorted tuple: %08x:%08x:%hu:%hu\n", \
                    sorted_tuple.src_ipv4.s_addr, \
                    sorted_tuple.dst_ipv4.s_addr, \
                    sorted_tuple.src_port, \
                    sorted_tuple.dst_port);
        case TCP6:
        case UDP6:
        default:
            break;
        } 

        if(packet_count % 100 == 0)
        {
            /* check another entry for expiry */
            //break; /* TODO: remove when done debugging */
        }
    }

    if(opts.debug)
        fprintf(stderr, "total packets handled: %llu\n", packet_count);
    if(opts.debug)
    {
        if (hashmap_count(ipv4_hashmap) > 0)
        {
            fprintf(stderr, "ipv4_hashmap has %ld maps on exit\n", hashmap_count(ipv4_hashmap));
            if (opts.verbose)
                hashmap_scan(ipv4_hashmap, ipv4_conn_iter, NULL);
        }
        if (hashmap_count(ipv6_hashmap) > 0)
        {
            fprintf(stderr, "ipv6_hashmap has %ld maps on exit\n", hashmap_count(ipv6_hashmap));
            if (opts.verbose)
                hashmap_scan(ipv6_hashmap, ipv6_conn_iter, NULL);
        }
    }

    pcap_close(in_handle);
    if(inject_handle)
        pcap_close(inject_handle);
    if(dump_handle)
        pcap_dump_close(dump_handle);
    hashmap_free(ipv4_hashmap);
    hashmap_free(ipv6_hashmap);

    return 0;
}
