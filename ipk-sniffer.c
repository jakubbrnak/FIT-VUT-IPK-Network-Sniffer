#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>

#include <getopt.h>
#include <signal.h>
#include <time.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>

/*2nd project for subject IPK, ZETA variant*/
/*Author: Jakub Brnak, xbrnak01 */


//global variable for storing handle for a network capture session 
pcap_t *handle;

//function for proper program termination in case of failure
void close_pcap_failure(){
    pcap_close(handle);
    exit(EXIT_FAILURE);
}

//function for proper program termination in case of success
void close_pcap_success(){
    pcap_close(handle);
    exit(EXIT_SUCCESS);
}

//function for printing mac adresses in required format
void print_mac(u_char mac_addr[6]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        mac_addr[0], mac_addr[1], mac_addr[2],
        mac_addr[3], mac_addr[4], mac_addr[5]);
}


//function for printing list of available interfaces    
void print_interfaces() {
    pcap_if_t *interfaces;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    for (d = interfaces; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i == 0) {
        printf("\nNo interfaces found! Make sure libpcap is installed.\n");
        exit(EXIT_FAILURE);
    }
    
        pcap_freealldevs(interfaces);
}

//function for printing information from ethernet header
void print_basic_info(struct ether_header *eth_header, struct pcap_pkthdr header) {
    char timebuffer[80];
    struct tm tm;

    gmtime_r(&header.ts.tv_sec, &tm);
    strftime(timebuffer, sizeof(timebuffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    printf("timestamp: %s\n", timebuffer);
    printf("src MAC: ");
    print_mac(eth_header->ether_shost);
    printf("dst MAC: ");
    print_mac(eth_header->ether_dhost);
    printf("frame length: %d\n",header.len);

}

//function for printing raw packet contents
void print_bytes(const u_char *packet, int len) {
    int packet_size = len;
    int line_size = 16;

    //for loop for intration in packet array
    for (int i = 0; i < packet_size; i++) {
        //print offset of a line 
        if (i % 16 == 0) {
            printf("\n0x%04X: ", i);
        } 
        //print byte of the packet
        printf("%02X", packet[i]);

        //print space if not at the end of line
        if (i % 16 != 15 && i != packet_size - 1) {
           printf(" ");
        } else {
                //print space padding if at the end of line
                printf(" ");
                if (i == packet_size - 1) {
                    int padding_size = (line_size - (packet_size % line_size)) % line_size;
                    for (int j = 0; j < padding_size; j++) {
                    printf("   ");
                    }
                }
            
                //print ascii representation of each byte in line
                for (int j = i - (i % 16); j <= i; j++) {
                printf("%c", isprint(packet[j]) ? packet[j] : '.');
            }
        }
    }
}

void start_sniffing(char *interface_name, char *filter_exp, int num){
        
    //error buffer for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];
    
    //data structure for compiled filter
    struct bpf_program fp;

    //data structure for packet header
    struct pcap_pkthdr header;
    
    //array for raw packet data
    const u_char *packet;

    //data structure for ethernet header
    struct ether_header *eth_header;

    //variable to store ether_type value from ethernet header
    unsigned short ether_type;

    //open interface for sniffing and check for fail
    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface_name, errbuf);
        exit(EXIT_FAILURE);
    }

    //connect signals to closing function
    signal(SIGINT, close_pcap_success);
    signal(SIGQUIT, close_pcap_success);
    signal(SIGTERM, close_pcap_success);

    //check if datalink layer is ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
	    fprintf(stderr, "Not an Ethernet header\n");
    	exit(EXIT_FAILURE);
    }

    //compile filter from filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    //install compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    //loop for loading and printing contents of jacked packets    
    for(int i = 0; i < num; i++){
       
       //catch packet and check for error
        packet = pcap_next(handle, &header);
        if(packet == NULL){
            fprintf(stderr, "Error in pcap_next: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        //cast packet to eth_header data structure to be able to extract important information
        eth_header = (struct ether_header *) packet;
        unsigned short ether_type = ntohs(eth_header->ether_type);
        
        //print newline to separate packets
        if(i != 0){
            printf("\n\n");
        }

        //print timestamp and mac addresses
        print_basic_info(eth_header, header);

       //switch for determining next actions based on value of EtherType
        switch (ether_type) {
            
            //if EtherType is IPv4
            case ETHERTYPE_IP:
                //casting packet to ip header with offset of ehter_header size to be able to extract important information
                struct ip *ip_header;
                ip_header = (struct ip *) (packet + sizeof(struct ether_header));
                
                //print source and destinantion ip address
                printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
                printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

                //switch for determining next actions based on value of ip protocol
                switch (ip_header->ip_p) {
                    
                    //if ip protocol is TCP
                    case IPPROTO_TCP:

                        //casting packet to tcphdr data structure with offset of ehter_header and ip_header to be able to extract important information
                        struct tcphdr *tcp_header;
                        tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));

                        //print source port and destinantion port 
                        printf("src port: %d\n", ntohs(tcp_header->th_sport));
                        printf("dst port: %d\n", ntohs(tcp_header->th_dport));

                        //print raw contents of packet
                        print_bytes(packet, header.len);
                        break;
                    
                    // if ip protocol is UDP
                    case IPPROTO_UDP:

                        //casting packet to udphdr data structure with offset of ehter_header and ip_header to be able to extract important information
                        struct udphdr *udp_header;
                        udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
                        
                        //print source port and destination port
                        printf("src port: %d\n", ntohs(udp_header->uh_sport));
                        printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                        
                        //print raw contents of packet
                        print_bytes(packet, header.len);
                        break;
                    
                    //if ip protocol is ICMP
                    case IPPROTO_ICMP:

                        //raw contents of packet
                        print_bytes(packet, header.len);
                        break;
                    
                    case IPPROTO_IGMP:
                        
                        //print raw contents of packet
                        print_bytes(packet, header.len);
                        break;
                    
                    default:
                        fprintf(stderr, "Unsupported IP protocol\n");
                        close_pcap_failure();
                        break;
                }
                break;
            
            //if EtherType is ARP
            case ETHERTYPE_ARP:

                //casting packet to erher_arp header with ethernet header offset to be able to extract important information
                struct ether_arp *arp_header;
                arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));
                
                //print source and destination ip address
                printf("src IP: %s\n", inet_ntoa(*(struct in_addr *) arp_header->arp_spa));
                printf("dst IP: %s\n", inet_ntoa(*(struct in_addr *) arp_header->arp_tpa));
                
                //print raw contents of packet
                print_bytes(packet, header.len);
                break;
            
            //if EtherTupe is IPv6
            case ETHERTYPE_IPV6:

                //casting packet to ip6_hdr data structore to be able to extract important informaiton 
                struct ip6_hdr *ip6_header;
                ip6_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

                //arrays for IPv6 addresses
                char src_ip6[INET6_ADDRSTRLEN];
                char dst_ip6[INET6_ADDRSTRLEN];
                
                //extracting IPv6 addresses from IPv6 header and converting to right format
                inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6, INET6_ADDRSTRLEN);
                
                //print source and destination IPv6 addreses
                printf("src IP: %s\n", src_ip6);
                printf("dst IP: %s\n", dst_ip6);
                
                //switch to determine next actions based on IP protocol number
                switch (ip6_header->ip6_nxt) {

                    //if ip protocol is TCP
                    case IPPROTO_TCP:
                        
                        //casting packet to tcphdr data structure with ethernet header and IPv6 header offset to be able to extract important information
                        struct tcphdr *tcp_header;
                        tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                        
                        //print source and destination port
                        printf("src port: %d\n", ntohs(tcp_header->th_sport));
                        printf("dst port: %d\n", ntohs(tcp_header->th_dport));
                       
                        //print raw packet contents
                        print_bytes(packet, header.len);
                        break;
                    
                    //ip ip protocol is UDP
                    case IPPROTO_UDP:

                        //casting packet to udphdr data structure with ethernet header and IPv6 header offset to be able to extract important information
                        struct udphdr *udp_header;
                        udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

                        //print source and destination port
                        printf("src port: %d\n", ntohs(udp_header->uh_sport));
                        printf("dst port: %d\n", ntohs(udp_header->uh_dport));
                        
                        //print raw packet contents
                        print_bytes(packet, header.len);
                        break;
                    
                    //if ip protocol is ICMP6
                    case IPPROTO_ICMPV6:

                        //print raw contents of packet
                        print_bytes(packet, header.len);
                        break;
                    
                    default:
                        fprintf(stderr, "Unsupported IP protocol\n");
                        close_pcap_failure();
                        break;
                }
                break;
            default:
                fprintf(stderr, "Unspported EtherType\n");
                close_pcap_failure();
                break;
        }    
   }
}



int main(int argc, char *argv[]) {
    
    //variable to store return value of getopt_long function
    int opt;
    
    //variable to store index of option being parsed by getopt_long funciton
    int option_index = 0;

    //flags for filter expression creation from command line options
    bool interface_flag = false;
    bool tcp_flag = false;
    bool udp_flag = false;
    bool port_flag = false;
    bool icmp4_flag = false;
    bool icmp6_flag = false;
    bool arp_flag = false;
    bool ndp_flag = false;
    bool igmp_flag = false;
    bool mld_flag = false;
    bool num_flag = false; 

    //variables to store values of options arguments
    char interface_name[256] = "";
    char port_name[256] = "";
    char num_name[256] = "";
    int num = 0;
        

    //array of option data structures for parsing long options
    struct option long_options[] = {
    {"interface", optional_argument, 0, 'i'},
    {"tcp", no_argument, 0, 't'},
    {"udp", no_argument, 0, 'u'},
    {"icmp4", no_argument, 0, '4'},
    {"icmp6", no_argument, 0, '6'},
    {"arp", no_argument, 0, 'a'},
    {"ndp", no_argument, 0, 'd'},
    {"igmp", no_argument, 0, 'g'},
    {"mld", no_argument, 0, 'm'},
    {0, 0, 0, 0}
    };

    //array to store filter expression
    char filter_exp[256] = "";

    //error buffer for pcap functions
    char errbuf[PCAP_ERRBUF_SIZE];

    //while loop for parsing command line options
    while ((opt = getopt_long(argc, argv, "i::p:n:tu", long_options, &option_index)) != -1) {
        switch (opt) {
            
            case 't':
                tcp_flag = true;
                break;
            case 'u':
                udp_flag = true;
                break;
            case 'p':
                port_flag = true;
                strcpy(port_name, optarg);
                break;
            case '4':
                icmp4_flag = true;
                break;
            case '6':
                icmp6_flag = true;
                break;
            case 'a':
                arp_flag = true;
                break;
            case 'd':
                ndp_flag = true;                
                break;
            case 'g':
                igmp_flag = true;
                break;
            case 'm':
                mld_flag = true;
                break;
            case 'n':
                num_flag = true;
                strcpy(num_name, optarg);
                break;
            case 'i':
                interface_flag = true;
                char *arg;

                //conditions to support space between optional argument and option itself
                if (optarg) {
                    arg = optarg;
                } else if (optind < argc && *argv[optind] != '-') {
                    arg = argv[optind++];
                } else {
                    arg = NULL;
                }
                
                
                if(arg == NULL){
                    
                    //check if other options are present, if not print available interfaces
                    if(argc <= 2){
                        print_interfaces();
                        exit(EXIT_SUCCESS);
                    }else{
                        fprintf(stderr,"Wrong argument of option -i\n");
                        fprintf(stderr, "Usage: /ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
                        exit(EXIT_FAILURE); 
                    }
                }
                strcpy(interface_name, arg);
                break;
            default:
                fprintf(stderr, "Usage: /ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
                exit(EXIT_FAILURE);
        }

    }

    //if there are no options specified, print available interfaces
    if(argc < 2 ){
        print_interfaces();
        exit(EXIT_SUCCESS);
    }else{

        //print error if there are some options without specified interface
        if(!interface_flag){
            fprintf(stderr, "Wrong combination of options used\n");
            fprintf(stderr, "Usage: /ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
            exit(EXIT_FAILURE);
        }

    }
    //check if port is used only when tcp or udp are also used
    if(port_flag && (!udp_flag && !tcp_flag)){
        fprintf(stderr,"Wrong use of -p parameter\n");
        fprintf(stderr,"Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
        exit(EXIT_FAILURE);
    }

    //build filter expression string using flags optained from argument parsing
    if(tcp_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "tcp");
    }
    
    if(udp_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "udp"); else strcat(filter_exp, " or udp");
    }

    if(icmp4_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "icmp"); else strcat(filter_exp, " or icmp");
    }

    if(icmp6_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "icmp6"); else strcat(filter_exp, " or icmp6");
    }

    if(arp_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "arp"); else strcat(filter_exp, " or arp");
    }

    if(ndp_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "(icmp6 and (icmp6[0] == 135 or icmp6[0] == 136))"); else strcat(filter_exp, " or (icmp6 and (icmp6[0] == 135 or icmp6[0] == 136))");
    }

    if(igmp_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "ip proto 2"); else strcat(filter_exp, " or ip proto 2");
    }

    if(mld_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "(icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132))"); else strcat(filter_exp, " or (icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132))");
    }

    if(port_flag){
        if(strlen(filter_exp) == 0)strcat(filter_exp, "port "); else strcat(filter_exp, " and port ");
        strcat(filter_exp, port_name);
    }

    //set number of packets to be sniffed
    if(num_flag){
        num = atoi(num_name);
    } else{
        num = 1;
    }

    //start sniffing specified number of packets on provided interface
    start_sniffing(interface_name, filter_exp, num);
    
    //close pcap after successful sniffing
    close_pcap_success();
        
    return 0;

}

    