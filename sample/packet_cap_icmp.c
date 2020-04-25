/*
 * パケットキャプチャサンプルコード
 * by shj@netwiz.jp
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

static void
print_ipheader(char *p)
{
    struct ip *ip;

    ip = (struct ip *)p;
    printf("ip_v = 0x%x\n", ip->ip_v);
    printf("ip_hl = 0x%x\n", ip->ip_hl);
    printf("ip_tos = 0x%.2x\n", ip->ip_tos);
    printf("ip_len = %d bytes\n", ntohs(ip->ip_len));
    printf("ip_id = 0x%.4x\n", ntohs(ip->ip_id));
    printf("ip_off = 0x%.4x\n", ntohs(ip->ip_off));
    printf("ip_ttl = 0x%.2x\n", ip->ip_ttl);
    printf("ip_p = 0x%.2x\n", ip->ip_p);
    printf("ip_sum = 0x%.4x\n", ntohs(ip->ip_sum));
    printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
    printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
    printf("\n");
}

static void
usage(char *prog)
{

    fprintf(stderr, "Usage: %s <device>\n", prog);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    pcap_t *handle;
    const unsigned char *packet;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct bpf_program fp;
    bpf_u_int32 net;

    if ((dev = argv[1]) == NULL)
        usage(argv[0]);

    /* 受信用のデバイスを開く */
    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    /* イーサネットのみ */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device not support: %s\n", dev);
        exit(EXIT_FAILURE);
    }    

    /* ICMPのみ受信するフィルターの設定をおこなう */
    if (pcap_compile(handle, &fp, "icmp", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* ループでパケットを受信 */
    while (1) {
        if ((packet = pcap_next(handle, &header)) == NULL)
            continue;

        /* イーサネットヘッダーとIPヘッダーの合計サイズに満たなければ無視 */
        if (header.len < sizeof(struct ether_header)+sizeof(struct ip))
            continue;
        print_ipheader((char *)(packet+sizeof(struct ether_header)));
    }

    /* ここに到達することはない */
    pcap_close(handle);
    return 0;
}
