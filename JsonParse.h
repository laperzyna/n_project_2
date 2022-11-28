
/* JsonParse.h builds off of our parser, jsmn.h. This file holds functions
that essentially get the contents of the config filen and return them in the type
they along with their corresponding variable so that they may be used.
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "jsmn.h"

#define MAX_SIZE_CONFIG_STRING 15
#define DEFAULT_UDP_SIZE 1000
#define DEFAULT_INTERMEASUREMENT_TIME 15
#define DEFAULT_UDP_PACKET_TRAIN_SIZE 6000
#define DEFAULT_UDP_TTL 255

typedef struct config
{
    char IP[MAX_SIZE_CONFIG_STRING];
    int sourcePort;
    int destPort;
    int destPortTCPHead;
    int destPortTCPTail;
    int portTCP;
    int udpPayloadSize;
    int interMeasurementTime;
    int numUDPPackets;
    int UDPPacketTTL;
} config;

#define MAX_NUM_TOKENS 50
jsmn_parser p;
// This is an array of tokens
jsmntok_t tokens[MAX_NUM_TOKENS]; /* We expect no more than 128 tokens */

int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

/* we pass in the structure as a pointer so that when we change the values it sticks */
void initializeConfig(config *c)
{
    // IP is a char array, if we don't put anything in the length is still 0 so
    // just check length to see if we filled it
    c->sourcePort = -1;
    c->destPort = -1;
    c->destPortTCPHead = -1;
    c->destPortTCPTail = -1;
    c->portTCP = -1;
    c->udpPayloadSize = -1;
    c->interMeasurementTime = -1;
    c->numUDPPackets = -1;
    c->UDPPacketTTL = -1;
}

// This function takes in a "string" that holds JSON data
// in the correct json format
int parseJSONFromString(char *JSON_STRING)
{
    jsmn_init(&p);
    int res = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), tokens,
                         sizeof(tokens) / sizeof(tokens[0]));
    if (res < 0)
    {
        printf("Failed to parse JSON: %d\n", res);
        exit(EXIT_FAILURE); // if the json cant be parsed we cant do anything
        // stop the program
    }
    return res;
}

/* saves JSON string */
void getStringFromJSON(char *json, char *saveString, int idxOfKeyInTArray)
{
    //"json" starts at the beginning of the JSON String pointer
    // but we have to offset to the start of the value we want
    // to get. The tokener array saves where all the different values
    // start so use the token data to move to the right spot
    json += tokens[idxOfKeyInTArray + 1].start;
    int numLetters = tokens[idxOfKeyInTArray + 1].end - tokens[idxOfKeyInTArray + 1].start;
    strncpy(saveString, json, numLetters);
    saveString[numLetters] = '\0';
}

/* saves JSON int */
int getIntFromJSON(char *json, int i)
{
    char saveString[MAX_SIZE_CONFIG_STRING];
    getStringFromJSON(json, saveString, i);
    return atoi(saveString);
}

// this function takes all the information in the config file
// and puts it into a char array
char *loadJSONConfigStringFromFile(char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("Error: could not open config json\n");
        exit(EXIT_FAILURE);
    }

    // we need to allocate enough space to save the JSON string in a
    // char array
    fseek(fp, 0, SEEK_END); // seek to end of file
    int size = ftell(fp);   // get current file pointer
    fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    char *jsonConfigString = (char *)malloc(sizeof(char) * (size + 1));
    // while we're NOT at the end of the file
    int idx = 0;
    while (idx < size)
    {
        char c = fgetc(fp);
        jsonConfigString[idx] = c;
        idx++;
    }
    // put in the null terminating
    jsonConfigString[idx] = '\0';
    return jsonConfigString;
}

void clearJsonMemory(char * jsonString){
    free(jsonString);
}

// this function will load the data from the config file
// into the config structure
void loadConfigStructFromConfigJSONString(char *jsonConfigString, config *c)
{
    // The third party library needs to fill it's tokener array based
    // on the JSOn string
    int numTokens = parseJSONFromString(jsonConfigString); // this should fill tokens[]

    // from printouts it seems like index 0 in the tokens array
    // is all of the data, the tokens actually start at 1
    //  the 1 at the end is for the first key in our json file
    // the 2 index is the value so all keys should be at
    // odd indexes
    for (int i = 1; i < numTokens; i++)
    {

        if (jsoneq(jsonConfigString, &tokens[i], "IP") == 0)
        {
            getStringFromJSON(jsonConfigString, c->IP, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "sourcePort") == 0)
        {
            c->sourcePort = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "destPort") == 0)
        {
            c->destPort = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "destPortTCPHead") == 0)
        {
            c->destPortTCPHead = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "destPortTCPTail") == 0)
        {
            c->destPortTCPTail = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "portTCP") == 0)
        {
            c->portTCP = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "udpPayloadSize") == 0)
        {
            c->udpPayloadSize = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "interMeasurementTime") == 0)
        {
            c->interMeasurementTime = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "numUDPPackets") == 0)
        {
            c->numUDPPackets = getIntFromJSON(jsonConfigString, i);
        }
        else if (jsoneq(jsonConfigString, &tokens[i], "UDPPacketTTL") == 0)
        {
            c->UDPPacketTTL = getIntFromJSON(jsonConfigString, i);
        }
        else
        {
            int numCharsInKey = tokens[i].end - tokens[i].start;
            printf("Key in the config file is not found: %.*s\n\n", numCharsInKey, jsonConfigString + tokens[i].start);
            exit(EXIT_FAILURE);
        }

        // assume that we got a correct token and read it in so skip the next token by
        // increasing i
        i++;
    }

    // check that we got at least the first 6 parameters in the config file
    if (strlen(c->IP) == 0)
    {
        printf("IP not found in the config file\n");
        exit(EXIT_FAILURE);
    }
    else if (c->sourcePort == -1)
    {
        printf("Source Port not found in the config file\n");
        exit(EXIT_FAILURE);
    }
    else if (c->destPort == -1)
    {
        printf("Destination Port not found in the config file\n");
        exit(EXIT_FAILURE);
    }
    else if (c->destPortTCPHead == -1)
    {
        printf("Destination Port TCP Head not found in the config file\n");
        exit(EXIT_FAILURE);
    }
    else if (c->destPortTCPTail == -1)
    {
        printf("Destination Port TCP Tail not found in the config file\n");
        exit(EXIT_FAILURE);
    }
    else if (c->portTCP == -1)
    {
        printf("Port TCP not found in the config file\n");
        exit(EXIT_FAILURE);
    } 

    //if we dont have a value for the other 4 use the default
    if (c->udpPayloadSize == -1){
        c->udpPayloadSize = DEFAULT_UDP_SIZE;
    } 
    if (c->interMeasurementTime == -1){
        c->interMeasurementTime = DEFAULT_INTERMEASUREMENT_TIME;
    }
    if (c->numUDPPackets == -1){
        c->numUDPPackets = DEFAULT_UDP_PACKET_TRAIN_SIZE;
    }
    if (c->UDPPacketTTL == -1){
        c->UDPPacketTTL = DEFAULT_UDP_TTL;
    }
}