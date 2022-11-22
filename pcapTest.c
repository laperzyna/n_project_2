#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

struct ipheader
{
    unsigned char ip_hl : 4, ip_v : 4; /* this means that each member is 4 bits */
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_id;
    unsigned short int ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short int ip_sum;
    unsigned int ip_src;
    unsigned int ip_dst;
}; 

struct tcpheader
{
    unsigned short int th_sport;
    unsigned short int th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_x2 : 4, th_off : 4;
    unsigned char th_flags;
    unsigned short int th_win;
    unsigned short int th_sum;
    unsigned short int th_urp;
}; 

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);


int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;
    pcap_t *handle;
    int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
     }
     
    printf("Entering pcap loop....\n");

    //set the filter for specific kinds of messages
    
    //tcp[tcpflags] will give the BITS that are set as flags
    //if we AND it with the tcp-rst and it equals tcp-rst then that means only the RST is set

    //tcpflags 0001   and tcp-rst is 0001
    // 1101 & 0001 = 1101
    //tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)


    //char filter_exp[] = "tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)";

    char filter_exp[] = "tcp";

    //use pcap_compile this to take the filter expression and
    //use that to set the filter stuctur correctly
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

     if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }


    if (fork() == 0){
        pcap_loop(handle, 0, my_packet_handler, NULL);
    }
    printf("Leaving pcap loop....\n");
    
    //wait for the forked process to finish
    wait(0);
    pcap_close(handle);
    return 0;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    //print_packet_info(packet_body, *packet_header);
    //printf("msg body: %s\n", packet_body);
    struct ipheader *iph = (struct ipheader *)packet_body;
    struct tcpheader *tcph = (struct tcpheader *)packet_body + sizeof(struct ipheader);
   // printf("Flags: %d   ", (int) tcph->th_flags);  
    int flagRes = (int) tcph->th_flags & TH_SYN;
    //printf(" anding with syn: %d ", flagRes);
    flagRes = (int) tcph->th_flags & TH_RST;
    //printf(" anding with RST: %d ", flagRes);
    if (flagRes == TH_RST && tcph->th_dport == 0){
        printf("RST PACKET on port %d\n", tcph->th_dport );
    }


}

/*

    class {

        (void *) parsingFunction(  u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body)



     }



*/

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}