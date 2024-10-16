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
    int l_octet_c[256] = {0}; //Array where the index represents the octet and the value represents the count of octet occurence

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
    //int i = 0;
    while ((packet = pcap_next(handle, &header)) != NULL) 
    {
    	if (header.len < sizeof(struct ethhdr) + sizeof(struct iphdr))
    	{
    		fprintf(stderr, "Packet %d is too small to contain an Ethernet and IP header\n", packet_count+1);
    		continue;
    	}
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        struct in_addr ip_dst;
        ip_dst.s_addr = ip_header->daddr;
        
        unsigned char l_octet = (ip_dst.s_addr >> 24) & 0xFF; // Retrieving last 8 bits by shifting the bits and adding a mask
        
        l_octet_c[l_octet]++; // Incrementing count of relevant octet
        
        //printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_dst));
        //i++;
    }
    pcap_close(handle);
    //Printing the octet and count if the octet exists
    for(int i = 0; i<256; i++)
    {
    	if(l_octet_c[i]>0)
    	{
    		printf("Last octet %d: %d\n",i,l_octet_c[i]);
    	}
    }
    return 0;
}

