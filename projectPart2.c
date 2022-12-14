#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include "jsmn.h"
#include "JsonParse.h"
#include <netinet/tcp.h>
#include <sys/time.h>

// define the ip header structure
/* IP Header */
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
}; /* total ip header length: 20 bytes (=160 bits) */

/* UDP Header */
struct udpheader
{
    unsigned short int uh_sport;
    unsigned short int uh_dport;
    unsigned short int uh_len;
    unsigned short int uh_check;
}; /* total udp header length: 8 bytes (=64 bits) */

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
}; /* total tcp header length: 20 bytes (=160 bits) */

config c;

/* 
we use the time library to get the current time in milliseconds so that we 
can start our timer and find compression
*/
long long millis()
{
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000; // calculate milliseconds
    return milliseconds;
}

/* this function generates header checksums */
unsigned short 
csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

/* This function sets up the ip and tcp header as it set their pointers */
void setupIPandTCPHeader(struct ipheader *iph, struct tcpheader *tcph, struct sockaddr_in addrSynHead, char *datagram, int destPort)
{
    iph->ip_hl = 5; // 0101
    iph->ip_v = 4;  // 0100      combined to make one unsignedchar    01010100
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); /* no payload */
    iph->ip_id = htonl(54321);                               /* the value doesn't matter here */
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = 6;
    iph->ip_sum = 0; /* set it to 0 before computing the actual checksum later */
    // TODO can this be anything? or should it also be the localhost addrSynHead
    iph->ip_src = inet_addr("127.0.0.1"); /* SYN's can be blindly spoofed */
    iph->ip_dst = addrSynHead.sin_addr.s_addr;
    tcph->th_sport = htons(1234); /* arbitrary port */
    tcph->th_dport = htons(destPort);
    tcph->th_seq = random(); /* in a SYN packet, the sequence is a random */
    tcph->th_ack = 0;        /* number, and the ack sequence is 0 in the 1st packet */
    tcph->th_x2 = 0;
    tcph->th_off = 0;            /* first and only tcp segment */
    tcph->th_flags = TH_SYN;     /* initial connection request */
    tcph->th_win = htonl(65535); /* maximum allowed window size */
    tcph->th_sum = 0;            /* if you set a checksum to zero, your kernel's IP stack
                            should fill in the correct checksum during transmission */
    tcph->th_urp = 0;

    iph->ip_sum = csum((unsigned short *)datagram, iph->ip_len >> 1);
}

/* 
This function sends the actual UDP packet train and depending on what we pass in it will send 
high or low entropy 
*/
void sendPacketTrain(int sockfd, config c, struct sockaddr_in *servaddr, char *dataToSend, int numPacketsToSend)
{
    // we need to make a packet ID, this is a 2 byte number
    // so we have to use bit shifting to split our
    // starting integer into 2 separate bytes
    //  [byte2 byte1] - 6000
    //  6000 in binary 00010111 01110000
    // to get each byte by itself we add it with 1's
    //                23       112
    //            00010111 01110000
    // idbyte1 &  00000000 11111111

    //           00010111 01110000
    // idbyte2 &  11111111 00000000
    // then bit shift to the right 8

    // we need to send multiple messages for use a for loop
    for (int packetID = 0; packetID < numPacketsToSend; packetID++)
    {

        // char can only hold 8 bits
        // so and the number with 8 1's using the 0xFF
        // and this gives us the right 8 bits
        unsigned char idByteRight = packetID & 0xFF;
        // Then we need the left 8 bits, so just shift the whole number
        // right 8 bits and do the same and as above
        unsigned char idByteLeft = (packetID >> 8); //& 0xFF;
        // the size of the message is the number from the config
        //+2 because we have a 2 byte packet id
        unsigned char udpPacket[c.udpPayloadSize + 2];
        udpPacket[0] = idByteLeft;
        udpPacket[1] = idByteRight;
        // dataToSend is either 0's or the random entropy data
        // dataToSend is size 10
        // copy the data into the udpPacket but dont go over
        // the ID
        strncpy(&udpPacket[2], dataToSend, c.udpPayloadSize);

        // MSG_CONFIRM is included in <sys/socket.h>
        sendto(sockfd, udpPacket, c.udpPayloadSize + 2, MSG_CONFIRM,
               (const struct sockaddr *)servaddr,
               sizeof(*servaddr));
    }
    printf("Sent packet train...\n");
}

/*
This function sends the SYN packets, which are TCP raw sockets
*/
void sendSYNPacket(int sockId,struct ipheader *iph, struct tcpheader *tcph, struct sockaddr_in addrSynHead, char *datagram, int destPort){
  // fill in the tcp and ip header information
    setupIPandTCPHeader(iph, tcph, addrSynHead, datagram, destPort);
    // at this point the way the pointers are setup the the ip and tcp header information SHOULD BE IN THE DATAGRAM
    // send low entropy packet train
     // send the tcp message
    if (sendto(sockId, datagram, iph->ip_len, 0, (struct sockaddr *)&addrSynHead, sizeof(addrSynHead)) < 0)
    {
        printf("error: could not send TCP Syn Head on raw socket\n");
    }
    else
    {
        printf("sent TCP Syn to port: %d\n", destPort);
    }
}

int main(int argc, char *argv[])
{
    //----LOAD JSON CONFIG FROM FILE
    // initialize all values to bad values so we can check later if we actually loaded them
    initializeConfig(&c);
    // loadJSON allocates memory for the json string to live based on the file length
    // so we need to free the JSON_STRING at the end of this program
    char *JSON_STRING = loadJSONConfigStringFromFile(argv[1]);
    loadConfigStructFromConfigJSONString(JSON_STRING, &c);

    //--setup socket info and options
    struct sockaddr_in addrSynHead;
    // setup SYN head address info
    addrSynHead.sin_family = AF_INET;
    addrSynHead.sin_port = htons(c.destPortTCPHead);
    addrSynHead.sin_addr.s_addr = inet_addr(c.IP);

     // setup the UDP socket information
    struct sockaddr_in addrUDP;
    addrUDP.sin_family = AF_INET;
    addrUDP.sin_port = htons(c.destPort);
    addrUDP.sin_addr.s_addr = inet_addr(c.IP);

    struct sockaddr_in addrSynTail;
    // setup SYN head address info
    addrSynTail.sin_family = AF_INET;
    addrSynTail.sin_port = htons(c.destPortTCPTail);
    addrSynTail.sin_addr.s_addr = inet_addr(c.IP);

    //------ OPEN ALL 3 SOCKETS -----

    //--- TCP RAW SOCKET TO SYN HEAD ----
    // NOTE: in order to open a RAW socket run the program with "sudo"
    int rawSockSYNHead = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawSockSYNHead < 0)
    {
        printf("Unable to create a socket\n");
        exit(EXIT_FAILURE);
    }

     // set the socket options so that the default IP and TCP header options are not automatically added
    // in front of all the options we just set
    // the setsockopt function wants a "const int *" so we need to make a variable that way we can make
    // a const int * to it
    int one = 1;
    if (setsockopt(rawSockSYNHead, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        printf("Warning: Cannot set HDRINCL in head!\n");
        exit(1); // leave the program
    }

     //--- UDP SOCKET FOR UDP PACKET TRAIN ----
    // Creating socket file descriptor
    int sockUDP;
    if ((sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    //  set the dont fragment flag
    int val = IP_PMTUDISC_DO;
    if(setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
        printf("Could not set sockopt for DONT FRAGMENT FLAG\n");
        exit(EXIT_FAILURE);
    };


    // set the TTL time
    int ttl = c.UDPPacketTTL; /* max = 255 */
    if ( setsockopt(sockUDP, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0){
        printf("Could not set sockopt for TTL\n");
        exit(EXIT_FAILURE);
    }

 //--- TCP RAW SOCKET TO SYN HEAD ----
    // NOTE: in order to open a RAW socket run the program with "sudo"
    int rawSockSYNTail = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawSockSYNTail < 0)
    {
        printf("Unable to create tail socket\n");
        exit(0);
    }

    one = 1;
    if (setsockopt(rawSockSYNTail, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        printf("Warning: Cannot set HDRINCL in tail!\n");
        exit(1); // leave the program
    }

    //---- SEND UDP PACKET TRAIN----
    /* this buffer will contain ip header, tcp header,
               and payload. we'll point an ip header structure
               at its beginning, and a tcp header structure after
               that to write the header values into it */
    char datagram[4096];
    // the ip header structure holds bytes (which is a char) so we're allowed to point
    // to the start of the datagram byte array
    // After printing out  sizeof(struct ipheader) we see that an IP HEADER is 20 bytes
    // so we can assume that the first 20 bytes in the datagram array
    // hold the ip header information
    struct ipheader *iph = (struct ipheader *)datagram;
    // After the first 20 bytes, comes the tcpheader so point the tcpheader structure to that part
    // of the datagram
    struct tcpheader *tcph = (struct tcpheader *)datagram + sizeof(struct ipheader);
    // make variable to hold SYN head address/port information   
    /* zero out the buffer */
    memset(datagram, 0, 4096);


    //--------PREPARE THE CHARCTER BUFFERS FOR LOW AND HIGH ENTROPY----------
    // prepare the UDP PAYLOAD options, we will add the ID's in front of this
    // All 0s
    unsigned char lowEntropy[c.udpPayloadSize];
    // use memset to fill this array with 0's
    // after the two ID bytes
    memset(lowEntropy, 0, c.udpPayloadSize);

    unsigned char highEntropy[c.udpPayloadSize];

    // Open the file with random numbers for high entropy
    FILE *fileRand = fopen("highEntropy", "r");
    // check to make sure it is open, exit program if not
    if (fileRand == NULL)
    {
        printf("Could not open the random file!\n");
        exit(1);
    }

    // the first two bytes are the ID so place these characters
    // start at index 2
    for (int i = 0; i < c.udpPayloadSize; i++)
    {
        char curByte;
        fscanf(fileRand, "%c", &curByte);
        highEntropy[i] = curByte;
    }


    //-------SEND THE ENTROPY PACKET TRAINS
    memset(datagram, 0, 4096);
    sendSYNPacket(rawSockSYNHead,iph,tcph,addrSynHead,datagram,c.destPortTCPHead);
    long long startTime = millis();

    sendPacketTrain(sockUDP, c, &addrUDP, lowEntropy, c.numUDPPackets);

     memset(datagram, 0, 4096);
    sendSYNPacket(rawSockSYNHead,iph,tcph,addrSynTail,datagram,c.destPortTCPTail);
    long long timeLowEntropy = millis() - startTime;


   int timeLeft = c.interMeasurementTime;
    while (timeLeft)
    {
        sleep(1);
        timeLeft--;
        printf("Waiting %d seconds to send second packet train...\n", timeLeft);
    }


    //clear the datagram to send the other packet's ip header information correctly
    memset(datagram, 0, 4096);
    sendSYNPacket(rawSockSYNHead,iph,tcph,addrSynHead,datagram,c.destPortTCPHead);
    startTime = millis();

    sendPacketTrain(sockUDP, c, &addrUDP, highEntropy, c.numUDPPackets);

    memset(datagram, 0, 4096);
    sendSYNPacket(rawSockSYNHead,iph,tcph,addrSynTail,datagram,c.destPortTCPTail);
    long long timeHighEntropy = millis() - startTime;

    //print time info
    long long timeDifference = timeHighEntropy - timeLowEntropy;
    //set the time difference and then check to see if it might be wrong
    //because lowEntropyTime was greater than high
    if (timeLowEntropy > timeHighEntropy){
        timeDifference = -1;
        printf("The low entropy time was greater than high\n");
    }

    printf("Time Difference:  %llu\n", timeDifference); 
    
  

    close(rawSockSYNHead);
    shutdown(rawSockSYNHead, SHUT_RDWR);


}
