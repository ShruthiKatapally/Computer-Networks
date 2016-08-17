#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <pcap/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/tcp.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <map>

#define MAX_SIZE_STRING 100
// Header size in words
#define MIN_SIZE_IP_HEADER  5
#define MAX_SIZE_IP_HEADER 15
#define MIN_SIZE_TCP_HEADER 5
#define SIZE_UDP_HEADER 2
#define SIZE_ICMP_HEADER 2
#define WORD_SIZE_BYTES 4
#define IPV4 4

struct statistics {
    // General information
    int count_packet;
    char date_string[MAX_SIZE_STRING];
    unsigned int smallest_packet_size;    
    unsigned int largest_packet_size;    
    double sum_packet_size;   
    time_t initial_time;
    time_t final_time;    
    // Link layer
    std::map<std::string, int> ethernet_source;
    std::map<std::string, int> ethernet_destination;
    // Network layer
    std::map<int, int> network_layer_protocol;
    std::map<std::string, int> ip_source;
    std::map<std::string, int> ip_destination;
    std::map<std::string, int> arp_id;
    // Transport layer
    std::map<std::string, int> transport_layer_protocol;
    std::map<int, int> source_tcp_port;
    std::map<int, int> destination_tcp_port;
    std::map<std::string, int> tcp_flags;
    std::map<int, int> source_udp_port;
    std::map<int, int> destination_udp_port;
    std::map<int, int> icmp_type;
    std::map<int, int> icmp_code;
};

void string_mac_address(const struct ether_addr *addr, char *address)
{
    // ether_ntoa prints out MAC address without the leading zeros.
    // Necessary to define our own function for printing out MAC address.
    sprintf(address,"%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
}

void print_summary(struct statistics *stat) {
	std::cout << "\n\n\n";
	std::cout << "===============Summary=============\n";
	std::cout << stat->date_string;
	std::cout << "Capture duration: " << (stat->final_time - stat->initial_time)
            << " seconds \n";
	std::cout << "Packets in capture: " << stat->count_packet << " \n";
	std::cout << "Minimum packet size: " << stat->smallest_packet_size << " \n";
	std::cout << "Maximum packet size: " << stat->largest_packet_size << " \n";
    std::cout.setf(std::ios::fixed, std:: ios::floatfield); 
    if (stat->count_packet > 0)
	    std::cout << "Average packet size: " << std::setprecision(2) 
            << (stat->sum_packet_size / stat->count_packet) << "\n\n\n";

    std::cout << "\n=========Link layer=========\n";
    std::cout << "\n---------Source ethernet addresses---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->ethernet_source.begin(); 
            it != stat->ethernet_source.end(); ++it) 
        std::cout << it->first << std::string(10, ' ') << it->second << std::endl;
    std::cout << "\n---------Destination ethernet addresses---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->ethernet_destination.begin();
             it != stat->ethernet_destination.end(); ++it) 
        std::cout << it->first << std::string(10, ' ') << it->second << std::endl;
    
    std::cout << "\n=========Network layer=========\n\n";
    std::cout << "---------Network layer protocols or payload size---------\n\n";
    for (std::map<int, int>::iterator it = stat->network_layer_protocol.begin(); 
            it != stat->network_layer_protocol.end(); ++it) {
        if (it->first == ETH_P_IP) {
            std::cout.width(40);
            std::cout << std::left << "IP" << it->second << std::endl;
        } else if (it->first == ETH_P_ARP) {
            std::cout.width(40);
            std::cout << std::left << "ARP" << it->second << std::endl;
        } else if (it->first < ETH_DATA_LEN) {
            std::cout << "Payload size: " << it->first <<  " (Ox" << std::hex << it->first
                    << std::dec << ")"  
                    << std::string(17, ' ') << it->second << std::endl;
        } else 
            std::cout << "Not identified protocol " <<it->first 
                    << " (Ox" << std::hex << it->first << ")" 
                    << std::dec << "   " << it->second << std::endl;
    }
    std::cout << "\n\n---------Source IP addresses---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->ip_source.begin(); 
            it != stat->ip_source.end(); ++it) {
        std::cout.width(40);
        std::cout << it->first << std::left << it->second << std::endl;
    }
    std::cout << "\n\n---------Destination IP addresses---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->ip_destination.begin(); 
            it != stat->ip_destination.end(); ++it) { 
        std::cout.width(40);
        std::cout << it->first << std::left << it->second << std::endl;
    }
    std::cout << "\n\n---------Unique ARP source address---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->arp_id.begin(); 
            it != stat->arp_id.end(); ++it) { 
        std::cout.width(40);
        std::cout << it->first << std::left << it->second << std::endl;
    }

    std::cout << "\n\n=========Transport layer=========\n\n";
    std::cout << "---------Transport layer protocols---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->transport_layer_protocol.begin(); 
            it != stat->transport_layer_protocol.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n\n=========Transport layer: TCP=========\n";
    std::cout << "\n---------Source TCP ports---------\n\n";
    for (std::map<int, int>::iterator it = stat->source_tcp_port.begin(); 
            it != stat->source_tcp_port.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n---------Destination TCP ports---------\n\n";
    for (std::map<int, int>::iterator it = stat->destination_tcp_port.begin(); 
            it != stat->destination_tcp_port.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n---------TCP flags---------\n\n";
    for (std::map<std::string, int>::iterator it = stat->tcp_flags.begin(); 
            it != stat->tcp_flags.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }

    std::cout << "\n\n=========Transport layer: UDP=========\n";
    std::cout << "\n---------Source UDP ports---------\n\n";
    for (std::map<int, int>::iterator it = stat->source_udp_port.begin(); 
            it != stat->source_udp_port.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n---------Destination UDP ports---------\n\n";
    for (std::map<int, int>::iterator it = stat->destination_udp_port.begin(); 
            it != stat->destination_udp_port.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }

    std::cout << "\n\n=========Transport layer: ICMP=========\n";
    std::cout << "\n---------ICMP types---------\n\n";
    for (std::map<int, int>::iterator it = stat->icmp_type.begin(); 
            it != stat->icmp_type.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n---------ICMP codes---------\n\n";
    for (std::map<int, int>::iterator it = stat->icmp_code.begin(); 
            it != stat->icmp_code.end(); ++it) {
        std::cout.width(40);
        std::cout << std::left << it->first << it->second << std::endl;
    }
    std::cout << "\n" << std::string(70, '~') << "\n\n";
}

void parse_packet(struct pcap_pkthdr *header,
        const unsigned char *pcap_packet, struct statistics *stat) {

    struct ethhdr *ethernet_header = (struct ethhdr *)pcap_packet; 

    if (header->len > stat->largest_packet_size)
        stat->largest_packet_size = header->len;
    if (header->len > 0 && header->len < stat->smallest_packet_size)
        stat->smallest_packet_size = header->len;
	stat->sum_packet_size += header->len;
	
    stat->count_packet++;
    time_t local_tv_sec = header->ts.tv_sec;
    struct tm *ltime = localtime(&local_tv_sec);
    char timestr[MAX_SIZE_STRING];
    strftime(timestr, MAX_SIZE_STRING, "%Y-%m-%d %H:%M:%S %Z", ltime);
    if (stat->count_packet == 1) {
        sprintf(stat->date_string,"Start date: %s \n", timestr);
        stat->initial_time = local_tv_sec;
    }
    stat->final_time = local_tv_sec;
	
    char mac_source[MAX_SIZE_STRING];
	string_mac_address((const struct ether_addr *)ethernet_header->h_source, mac_source);
    stat->ethernet_source[mac_source]++;
    char mac_destination[MAX_SIZE_STRING];
	string_mac_address((const struct ether_addr *)ethernet_header->h_dest, mac_destination);
    stat->ethernet_destination[mac_destination]++;

    if (header->len < ETH_HLEN) {
        // Packet is too short for Ethernet frame header
        return;
    }    
    // Read type field for Ethernet frame
    int ethernet_type_field = ntohs(ethernet_header->h_proto);
    stat->network_layer_protocol[ethernet_type_field]++;
    
    if (ethernet_type_field == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(pcap_packet + ETH_HLEN); 
        if (ip->ihl < MIN_SIZE_IP_HEADER || 
                (ETH_HLEN + ip->ihl*WORD_SIZE_BYTES) > header->len) {
            return;
        }    
        if (ip->version > IPV4) {
            // If not IPv4, silently ignore the rest of datagram
            return;
        }    
        stat->ip_source[inet_ntoa(*(struct in_addr *) &ip->saddr)]++;
        stat->ip_destination[inet_ntoa(*(struct in_addr *) &ip->daddr)]++;
    
        if (ip->protocol == IPPROTO_TCP) {
            int tcp_offset = ETH_HLEN + ip->ihl*WORD_SIZE_BYTES;
            if ((tcp_offset + MIN_SIZE_TCP_HEADER*WORD_SIZE_BYTES) > header->len)
                return;
            struct tcphdr *tcp = (struct tcphdr *) 
                    (pcap_packet + tcp_offset);
            stat->transport_layer_protocol["TCP"]++; 
            stat->source_tcp_port[ntohs(tcp->source)]++; 
            stat->destination_tcp_port[ntohs(tcp->dest)]++;
            stat->tcp_flags["ACK"] += tcp->ack; 
            stat->tcp_flags["FIN"] += tcp->fin; 
            stat->tcp_flags["PSH"] += tcp->psh; 
            stat->tcp_flags["RST"] += tcp->rst; 
            stat->tcp_flags["SYN"] += tcp->syn; 
            stat->tcp_flags["URG"] += tcp->urg; 
        } else if (ip->protocol == IPPROTO_UDP) {       
            int udp_offset = ETH_HLEN + ip->ihl*WORD_SIZE_BYTES;
            if ((udp_offset + SIZE_UDP_HEADER*WORD_SIZE_BYTES) > header->len)
                return;
            struct udphdr *udp = (struct udphdr *) 
                (pcap_packet + ETH_HLEN + ip->ihl*WORD_SIZE_BYTES);
            stat->transport_layer_protocol["UDP"]++; 
            stat->source_udp_port[ntohs(udp->source)]++; 
            stat->destination_udp_port[ntohs(udp->dest)]++;
        } else if (ip->protocol == IPPROTO_ICMP) {       
            int icmp_offset = ETH_HLEN + ip->ihl*WORD_SIZE_BYTES;
            if ((icmp_offset + SIZE_ICMP_HEADER*WORD_SIZE_BYTES) > header->len)
                return;
            stat->transport_layer_protocol["ICMP"]++; 
            struct icmphdr *icmp = (struct icmphdr *) 
                (pcap_packet + ETH_HLEN + ip->ihl*WORD_SIZE_BYTES);
            stat->icmp_type[icmp->type]++; 
            stat->icmp_code[icmp->code]++;
        }  else {
            char protocol_string[MAX_SIZE_STRING];
            snprintf(protocol_string, MAX_SIZE_STRING, "%d", ip->protocol);
            stat->transport_layer_protocol[protocol_string]++; 
        }
    } else if (ethernet_type_field == ETH_P_ARP) {
        const int offset_mac_arp = 8;
        const struct ether_addr *arp_mac_source =
            (const struct ether_addr *) (pcap_packet + ETH_HLEN + offset_mac_arp); 
        char arp_mac_source_string[MAX_SIZE_STRING];
	    string_mac_address(arp_mac_source, arp_mac_source_string);
        char *arp_ip_source_string = (char *) malloc(MAX_SIZE_STRING);
        const int offset_ip_arp = 14;
        arp_ip_source_string = (char *) inet_ntoa(
                    *(struct in_addr *)(pcap_packet + ETH_HLEN + offset_ip_arp));
        char arp_id[MAX_SIZE_STRING];
        sprintf(arp_id,"%s \\ %s ", arp_mac_source_string, arp_ip_source_string);
        stat->arp_id[arp_id]++;
    }
}

pcap_t *parse_options(int argc,  char * argv[]) {
    int c;
    //char filename[100];
    char *filename = (char *) malloc(MAX_SIZE_STRING);
    int name_set = 0;

    while (1) {
        static struct option long_options[] = {
            {"help", no_argument      , 0, 'h'},
            {"open", required_argument, 0, 'o'},
            {0, 0, 0, 0}
        };
        int index_to_option = 0;

        c = getopt_long (argc, argv, "h:o:",
                       long_options, &index_to_option);

        if (c == -1)
            break;

        switch (c) {
            case 'h':
            std::cout << "Wiretap analyzes captured packets\n"; 
            std::cout << "Options: --help                   show help message\n"; 
            std::cout << "Options: --open  <packet_file>    open packet file \n"; 
            break;

            case 'o':
            strncpy(filename, optarg, MAX_SIZE_STRING);
            name_set = 1;
            break;
        
            default:
            exit(1);
        }
    }     
  
    char errbuff[PCAP_ERRBUF_SIZE];
    if (name_set) {
        return (pcap_open_offline(filename,errbuff));
    } else {
        std::cout << "Usage: ./wiretap --open <packet_file>  \n"; 
        exit(1);
    }
}

int main(int argc,char *argv[]) {
    if (argc == 1) {
        std::cout << "Usage: ./wiretap --open <packet_file>  \n"; 
    }
    pcap_t *pcap_handler = parse_options(argc, argv);

    if(pcap_handler == NULL) {
        std::cout << "Error in opening a file: " << argv[2] << " \n";  
	    return -2;
    }
    int status_read;
    const unsigned char *pcap_packet;
    struct pcap_pkthdr *header;
    statistics *stat = new statistics();
    stat->count_packet = 0;
    stat->smallest_packet_size = INT_MAX;    
    stat->largest_packet_size = 0;    
    stat->sum_packet_size = 0;   
    
    while((status_read = pcap_next_ex(pcap_handler,&header,&pcap_packet)) == 1) {
        parse_packet(header, pcap_packet, stat);
	}
    pcap_close(pcap_handler);
    print_summary(stat);

    if (status_read == -1) {
        printf("Error reading the packet: %s \n", pcap_geterr(pcap_handler));
        return -3; 
    }
    return 0;
}

