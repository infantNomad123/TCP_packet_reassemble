# TCP_packet_reassemble
A project that demonstrates TCP packet reassembly from scratch. It uses the Murmur3 hashing algorithm to ensure low collision rates and optimized speed, paired with a custom hash table layout for highly efficient array index mapping and memory allocation.

TCP packet is indispensable in the world of internet. Every infos that comes and goes across the network requires TCP for the reliable connection. TCP packet when exceeds the wire limit(1500 bytes) is chopped up. So the massive TCP packets that comes through gets fragmented and need to be reassembled again once reaching the destination. 
