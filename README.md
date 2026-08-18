# TCP Packet Reassembly Engine

TCP packet is indispensable in the world of internet. Every infos that comes and goes across the network requires TCP for the reliable connection. TCP packet when exceeds the wire limit(1500 bytes) is chopped up. So the massive TCP packets that comes through gets fragmented and need to be reassembled again once reaching the destination

This project implements high-performance and from-scratch implementation of a TCP packet reassembly engine, demonstrating how to track, capture and reconstruct the fragmented network streams efficiently using low-level memory layouts and optimized hashing technique.

## Key features
* **Zero-dependency reconstruction:** Reconstructs the stream from scratch without relying on the heavy external network stacks.
* **Murmur3 hashing algorithms:** To ensure the low collision rate and also optimized speed.
* **Custom hash table:** Features a cache-friendly hash array index mapping system to optimize memory allocations and lookup.

## Architecture & Design
```
typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flowtracker;
```

### Core Data Layout
```[language]
// Insert primary struct, class, or schema here
```

## Getting Started

### Prerequisites
* [e.g., Node.js v18+, GCC 11+, Docker]

### Installation
```bash
git clone https://github.com
cd repo
make setup
```

## 💻 Usage Example
```[language]
// Shortest copy-pasteable working snippet
```

## 📜 License
Distributed under the [MIT/Apache 2.0] License. See `LICENSE` for details.
