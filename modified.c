#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[]) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;

    if (argc != 2) 
    {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    
    while ((packet = pcap_next(handle, &header)) != NULL) 
    {
    	// Checking if the packet is large enough to store the ethernet + ip header values
    	if (header.len < sizeof(struct ethhdr) + sizeof(struct iphdr))
    	{
    		fprintf(stderr, "Packet %d is too small to contain an Ethernet and IP header\n", packet_count+1);
    		continue;
    	}
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr)); //Moving pointer to where the IP header starts (after ethernet header)
        struct in_addr ip_dst; //Creating a variable of type in_addr to store the destination address
        ip_dst.s_addr = ip_header->daddr; //Storing the destination address
        
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_dst)); //inet_ntoa converts the dst address into human readable form
        
    }

    pcap_close(handle);
    return 0;
}

