#pragma once

#include <arpa/inet.h>
#include <cstdint>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t s_port;
	uint16_t d_port; 
	uint32_t seq_number;  
	uint32_t ack_number; 

	uint8_t reserved:4; 
    uint8_t offset:4;

	uint8_t tcp_flags; 
	uint16_t window;   
	uint16_t checksum;  
	uint16_t urgent_ptr; 

	uint8_t header_len() const {
		return offset * 4;
	}
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
