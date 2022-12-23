#pragma once

// Defining a structure for the global header
struct pcap_global_header {
    unsigned int magic_number;   /* magic number (4 bytes)*/
    unsigned short version_major;  /* major version number (2 bytes) */
    unsigned short version_minor;  /* minor version number (2 bytes)*/
    unsigned int  thiszone;       /* GMT to local correction (4 bytes)*/
    unsigned int sigfigs;        /* accuracy of timestamps (4 bytes)*/
    unsigned int snaplen;        /* max length of captured packets, in octets (4 bytes)*/
    unsigned int network;        /* data link type (4 bytes)*/
};

pcap_global_header get_global_header(const char*);
void print_global_header(pcap_global_header);
