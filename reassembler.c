                                                                                                                                                                                                                                                                                                                                                                                                                                                          tuples2.c *
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <sys/socket.h>

#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))
#define HASH_SEED 42
#define TABLE_SIZE 65536

// 5-Tuple Structure
typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flowtracker;


typedef struct {
    flowtracker key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint8_t *slot;
    struct oo_fragment *ooo_queue;
    uint32_t buffer_max_size;
    uint32_t initial_sequence;
    uint32_t next_expected_seq;
    int is_active;
} flowentry;

flowentry flowtable[TABLE_SIZE] = {0};

void printPacket(const uint8_t *packet, struct pcap_pkthdr *header);



void packetReassembly(const uint8_t *packet, struct iphdr *ipheader, flowentry *entry, struct pcap_pkthdr *header);

// The MurmurHash3 Hashing Function Definition
uint32_t hash(const flowtracker* tuple, uint32_t seed) {
    uint32_t h1 = seed;
    uint32_t c1 = 0xcc9e2d51; //Prime number, block multiplier
    uint32_t c2 = 0x1b873593; //Prime number, block multiplier
    uint32_t k1;
    const uint8_t* data = (const uint8_t*)tuple;

    __builtin_memcpy(&k1, &data[0], 4); // Copy data into a variable memory
    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    //To ensure that the hash keep changing
    h1 = h1 * 5 + 0xe6546b64;

    __builtin_memcpy(&k1, &data[4], 4);
    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2; h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;

    __builtin_memcpy(&k1, &data[8], 4);
    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;

    uint32_t k2 = 0;
    k2 ^= data[12];
    k2 *= c1;
    k2 = ROTL32(k2, 15);
    k2 *= c2;
    h1 ^= k2;

    //13 is the exact total lengty in bytes of flowtracker struct
    //Scrambles bits
    h1 ^= 13;

    //Mixes the heavily scrambled top half(16 bits) to the bottom half(16 bits)
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;

    //Break the redundant pattern left behind
    h1 ^= h1 >> 13;


    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    return h1;
}

void getIpaddress( struct iphdr *ipheader){
        char src_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ipheader->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ipheader->daddr, dest_ip, sizeof(dest_ip));

        printf("Source IP: %s ", src_ip);
        printf("Dest IP: %s\n ", dest_ip);

}

void packetCallback(uint8_t *user_args, const struct pcap_pkthdr *pkthdr, const uint8_t *packet, struct pcap_pkthdr *header) {
    (void)user_args;
    const uint32_t eth_header_len = 14;


    struct iphdr *ipheader = (struct iphdr *)(packet + eth_header_len);
    if (ipheader->version != 4) return;

    uint8_t protocol = ipheader->protocol;
    if (protocol != 6) return; // Only process TCP (6) for stream reassembly
 if (__builtin_memcmp(&entry->key, &temp_flow, sizeof(flowtracker)) == 0) {
            entry->packet_count++;
            entry->byte_count += pkthdr->len;
            printf("[UPDATED ] Memory Slot: %5u | Packets: %lu\n", index, entry->packet_co>
        }
    uint32_t ip_header_len = ipheader->ihl * 4;
    const uint8_t* l4_header = packet + eth_header_len + ip_header_len;

    // Create 5-tuple key instance
    /*flowtracker temp_flow;
    __builtin_memcpy(&temp_flow.src_ip, &ipheader->saddr, 4);
    __builtin_memcpy(&temp_flow.dst_ip, &ipheader->daddr, 4);
    __builtin_memcpy(&temp_flow.src_port, &l4_header[0], 2);
    __builtin_memcpy(&temp_flow.dst_port, &l4_header[2], 2);
    temp_flow.protocol = protocol;*/

    // Create 5-tuple key instance with Flow Normalization
    flowtracker temp_flow;

    // Sort by IP address so upload and download yield the exact same hash
    if (ipheader->saddr < ipheader->daddr) {
       temp_flow.src_ip = &ipheader->saddr;
       temp_flow.dst_ip = &ipheader->daddr;
       temp_flow.src_port = l4_header;
       temp_flow.dst_port = l4_header + 2;
    } else {
        temp_flow.src_ip = &ipheader->daddr;
        temp_flow.dst_ip = &ipheader->saddr;
        temp_flow.src_port = l4_header + 2;
        temp_flow.dst_port = l4_header;
    }
    temp_flow.protocol = protocol;


    // Compute hash array index mapping
    uint32_t hash_val = hash(&temp_flow, HASH_SEED);
    uint32_t index = hash_val % TABLE_SIZE;

    flowentry *entry = &flowtable[index];

    if (entry->is_active == 0) {
        struct tcphdr *tcp = (struct tcphdr *)l4_header;
        if (tcp->syn && !tcp->ack) {
            entry->key = temp_flow;
            entry->packet_count = 1;
            entry->byte_count = pkthdr->len;
            entry->is_active = 1;

            entry->buffer_max_size = 1024 * 1024; // 1 MB Allocation
            entry->slot = malloc(entry->buffer_max_size);
            if (entry->slot == NULL) {
                entry->is_active = 0;
                return;
            }
            printf("[NEW FLOW] Memory Slot: %5u | Protocol: TCP\n", index);
        } else {
            return;
        }
    } else {
        if (__builtin_memcmp(&entry->key, &temp_flow, sizeof(flowtracker)) == 0) {
            entry->packet_count++;
            entry->byte_count += pkthdr->len;
            printf("[UPDATED ] Memory Slot: %5u | Packets: %lu\n", index, entry->packet_count);
        } else {
            printf("[COLLISION DETECTED] at Memory Slot: %u\n", index);
            return;
        }
    }

    packetReassembly(packet, ipheader, entry, header);
}

void packetReassembly(const uint8_t *packet, struct iphdr *ipheader, flowentry *entry, struct pcap_pkthdr *header) {
    uint32_t ip_header_len = ipheader->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);

    uint32_t current_seq = ntohl(tcp->seq);


    uint32_t tcp_header_len = tcp->doff * 4;

    uint16_t ip_total_len = ntohs(ipheader->tot_len);
    uint32_t payload_len = ip_total_len - ip_header_len - tcp_header_len;
    const unsigned char *payload = (const unsigned char *)tcp + tcp_header_len;

    // Handle session baseline assignments on SYN verification
    if (tcp->syn && !tcp->ack) {
        entry->initial_sequence = current_seq;
        entry->next_expected_seq = current_seq + 1;
        printf("Connection initialized. ISN Saved: %u\n", entry->initial_sequence);
        return;
    }


    else if (payload_len > 0) {
        uint32_t buffer_offset = current_seq - entry->initial_sequence;

        //Prevent from buffer overload
        if (buffer_offset + payload_len > entry->buffer_max_size) {
            return;
        }

        memmove(entry->slot + buffer_offset, payload, payload_len);

        if (current_seq == entry->next_expected_seq) {
            entry->next_expected_seq += payload_len;
            uint32_t total_assembled = entry->next_expected_seq - entry->initial_sequence - 1;
            getIpaddress(ipheader);
            printf("[REASSEMBLED] In-order segment appended. Stream grew to %u bytes.\n", total_assembled);
            //print_packet(packet,header);
        } else if (current_seq > entry->next_expected_seq) {
            printf("[GAP DETECTED] Packet landed ahead in buffer. Missing sequence range: %u to %u\n",
                   entry->next_expected_seq, current_seq);
        }
    }

    if (tcp->fin || tcp->rst) {
        entry->is_active = 0;
        uint32_t final_stream_size = entry->next_expected_seq - entry->initial_sequence - 1;
        printf("[STREAM FINISHED] Reassembly complete. Connection closed. Total payload: %u bytes.\n", final_stream_size);
        // Clean up allocation block safely to avoid massive system memory leaks
        free(entry->slot);
        entry->slot = NULL;
    }
}

void printPacket(const uint8_t *packet,  struct pcap_pkthdr *header){
        int align = 0;
        for(int i =0; i < header->caplen; i++){
                align++;
                printf("%02X " , packet[i]);
                if(align == 4){
                        align =0;
                        printf("\n");
                }
        //      printf("\n");
        }
}

// Main caputre runtime layer
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    const uint8_t *packet;

    struct pcap_pkthdr *header;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    char *dev_name = alldevs->name;
    if (dev_name == NULL) {
        fprintf(stderr, "No available interface devices found.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("Opening interface engine on device: %s\n", dev_name);

    pcap_t *handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev_name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);
    printf("Sniffing network packets... Press Ctrl+C to stop.\n");



int res;

    // Explicit while loop layout substituting pcap_loop execution
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) {
            continue; // Live interface read timeout elapsed
        }

        // Pass four explicit arguments down into your packet handling structure
        packetCallback(NULL, header, packet, (struct pcap_pkthdr *)header);
    }

    if (res == -1) {
        fprintf(stderr, "Error reading packets: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}

