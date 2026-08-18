# TCP Packet Reassembly Engine

TCP packet is indispensable in the world of internet. Every infos that comes and goes across the network requires TCP for the reliable connection. TCP packet when exceeds the wire limit(1500 bytes) is chopped up. So the massive TCP packets that comes through gets fragmented and need to be reassembled again once reaching the destination

This project implements high-performance and from-scratch implementation of a TCP packet reassembly engine, demonstrating how to track, capture and reconstruct the fragmented network streams efficiently using low-level memory layouts and optimized hashing technique.

## Key features
* **Zero-dependency reconstruction:** Reconstructs the stream from scratch without relying on the heavy external network stacks.
* **Murmur3 hashing algorithms:** To ensure the low collision rate and also optimized speed.
* **Custom hash table:** Features a cache-friendly hash array index mapping system to optimize memory allocations and lookup.

