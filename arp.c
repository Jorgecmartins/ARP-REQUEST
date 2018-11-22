#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap/pcap.h>
#include <pthread.h>

#define PROMISC 1
#define ETH_SIZE 14
#define ARP_BROADCAST "00:00:00:00:00:00"
#define ETH_BROADCAST "ff:ff:ff:ff:ff:ff"

typedef unsigned char u_char;
typedef struct arp_hdr {
    u_int16_t  ht; /*Hardware type */
    u_int16_t  pt; /*Protocol type*/
    u_char    hal; /*Hardware address length*/
    u_char    pal; /*Protocol address length*/
    u_int16_t  op; /*Operation code*/
    u_char sha[6]; /*Sender hardware address*/
    u_char spa[4]; /*Sender ip address*/
    u_char tha[6]; /*Target hardware address*/
    u_char tpa[4]; /*Target ip address*/
} arphdr_t;

int end = 0;
struct in_addr src_ip;
struct in_addr dst_ip;
char* device;

int 
compare_ip(u_int32_t* ip1, u_int32_t* ip2) {
    return *ip1 == *ip2;
}

u_int32_t 
char_int32(u_char* ip) {
    return (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
}

void 
check_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_t* handle = (pcap_t*) args;
    struct libnet_ethernet_hdr* eth;
    arphdr_t* arp;
    int arp_pt = 0, i;
    struct in_addr spa, tpa;

    eth = (struct libnet_ethernet_hdr*) packet;
    arp = (arphdr_t*) (packet + ETH_SIZE);
    arp_pt = ntohs(arp->op);

    if(ntohs(arp->pt) == 0x0800 && ntohs(arp->ht) == 1){
        if ( arp_pt == ARPOP_REPLY ) {
            spa.s_addr = char_int32(arp->spa);
            tpa.s_addr = char_int32(arp->tpa);

            if (compare_ip(&spa.s_addr, &dst_ip.s_addr) &&
                    compare_ip(&tpa.s_addr, &src_ip.s_addr)) {
                end = 1;
                printf("Physical address of %s is:\n",inet_ntoa(dst_ip));
                for(i = 0; i < 6; i++)
                    printf("%02x.", arp->tha[i]);
                puts("");
                pcap_breakloop(handle); 
            }
        }
    }
}

void 
*thread_func(void* arg) {
    char pcap_err_buff[PCAP_ERRBUF_SIZE];
    char filter[] = "arp";
    pcap_t* handle;
    bpf_u_int32 net, mask;
    struct bpf_program fp;

    //Initialize pcap

    if (pcap_lookupnet(device, &net, &mask, pcap_err_buff) == -1) {
        fprintf(stderr, "Can't get netmask for device: %s\n", device);
        exit(EXIT_FAILURE);
    }
    if ((handle = pcap_open_live(device, BUFSIZ, PROMISC, 1000, pcap_err_buff)) == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, pcap_err_buff);
        exit(EXIT_FAILURE);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", device);
        exit(EXIT_FAILURE);
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, check_packet, (u_char*)handle);
    pcap_close(handle);
    return NULL;
}

int 
main(int argc, char* argv[]) {
    pthread_t capture_thread = NULL;
    libnet_t* context;
    libnet_ptag_t arp;
    libnet_ptag_t eth;
    struct libnet_ether_addr* pc_hw_addr;
    u_int8_t* arp_dst_mac;
    u_int8_t* eth_dst_mac;
    char libnet_err_buff[LIBNET_ERRBUF_SIZE];
    int r;

    //    Initialize libnet
    device = argv[2];

    if (inet_aton(argv[1], &dst_ip) == 0) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }
    if ((arp_dst_mac = libnet_hex_aton(ARP_BROADCAST, &r)) == NULL) {
        fprintf(stderr, "MAC address error\n");
        exit(EXIT_FAILURE);
    }
    if ((eth_dst_mac = libnet_hex_aton(ETH_BROADCAST, &r)) == NULL) {
        fprintf(stderr, "MAC address error\n");
        exit(EXIT_FAILURE);
    }
    if ((context = libnet_init(LIBNET_LINK, "en0", libnet_err_buff)) == NULL) {
        fprintf(stderr, "Failed: %s", libnet_err_buff);
        exit(EXIT_FAILURE);
    } 
    if ((pc_hw_addr = libnet_get_hwaddr(context)) == NULL) {
        fprintf(stderr,"Error: %s",libnet_geterror(context));
        exit(EXIT_FAILURE);
    }

    if ((src_ip.s_addr = libnet_get_ipaddr4(context)) == -1) {
        fprintf(stderr, "Error: %s", libnet_geterror(context));
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&capture_thread, NULL, thread_func, NULL) != 0) {
        fprintf(stderr, "Unable to create thread\n");
        exit(EXIT_FAILURE);
    }

    while (1) {

        arp = libnet_autobuild_arp(
                ARPOP_REQUEST,
                (u_int8_t *)pc_hw_addr,
                (u_int8_t *)&(src_ip.s_addr),
                arp_dst_mac,
                (u_int8_t *)&(dst_ip.s_addr),
                context);

        if (arp == -1) {
            fprintf (stderr,"Unable to build ARP header: %s\n", libnet_geterror(context));
            exit(EXIT_FAILURE);
        }

        eth = libnet_autobuild_ethernet(
                eth_dst_mac,
                ETHERTYPE_ARP,
                context);

        if (eth == -1) {
            fprintf(stderr, "Unable to build ETH header: %s\n", libnet_geterror(context));
            exit(EXIT_FAILURE);
        }

        r = libnet_write(context);
        if (r == -1) {
            fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(context));
            exit(EXIT_FAILURE);
        } 

        libnet_clear_packet(context);
        if(end)
            break;
        sleep(1);
    }

    libnet_destroy(context);
    pthread_join(capture_thread, NULL);
    free(arp_dst_mac);
    free(eth_dst_mac);
    exit(EXIT_SUCCESS);
}

