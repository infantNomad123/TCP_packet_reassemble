# TCP Packet Reassembly Engine

TCP packet is indispensable in the world of internet. Every infos that comes and goes across the network requires TCP for the reliable connection. TCP packet when exceeds the wire limit(1500 bytes) is chopped up. So the massive TCP packets that comes through gets fragmented and need to be reassembled again once reaching the destination

This project implements high-performance and from-scratch implementation of a TCP packet reassembly engine, demonstrating how to track, capture and reconstruct the fragmented network streams efficiently using low-level memory layouts and optimized hashing technique.

## Key features
* **Zero-dependency reconstruction:** Reconstructs the stream from scratch without relying on the heavy external network stacks.
* **Murmur3 hashing algorithms:** To ensure the low collision rate and also optimized speed.
* **Custom hash table:** Features a cache-friendly hash array index mapping system to optimize memory allocations and lookup.

## Architecture & Design
### Core Data Layout
#### 5 tuple data structure
```
typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flowtracker;
```
Captures core data from the tcp header - Source IP, Destination IP, Source Port, Destination Port and Protocol (6 or 17)

#### Hashing using Murmur3 Algorithm
```
 __builtin_memcpy(&k1, &data[0], bytes); // Copy data into a variable memory
    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    //To ensure that the hash keep changing
    h1 = h1 * 5 + 0xe6546b64;
```
This code is where the mixing of the bits happens. By moving 15 and 13 positions to the right, it ensures that it doesn't generate similar hashes and avoid collisions. Therefore captured attributes from the TCP header (above) are combined into a single hash that also helps in low collision rate and speed optimization during the process. This also maintains memory efficiency.

#### Entry table 

```
typedef struct {
    flowtracker key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint8_t *slot;
    uint32_t buffer_max_size;
    uint32_t initial_sequence;
    uint32_t next_expected_seq;
    int is_active;
} flowentry;
```

## License
Copyright © 2026. All rights reserved. This code is for viewing purposes only. No unauthorized reproduction, distribution, or execution is permitted.

