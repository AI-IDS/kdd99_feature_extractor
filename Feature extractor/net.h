#pragma once

#include <stdint.h>
extern "C" {
#include <pcap.h>
}
//#ifdef _WIN32
//#include <winsock.h>
//#endif // _WIN32

/*
 * Structs for parsing network headers
 * Inspired by http://stackoverflow.com/a/16523804/3503528
 */
namespace FeatureExtractor {
	/*
	 * Ethernet type/length field
	 */
	enum eth_field_type_t : uint16_t {
		TYPE_ZERO = 0,
		MIN_ETH2 = 0x600,
		IPV4 = 0x800
	};

	/*
	 * Ethernet header
	 */
	typedef struct {
		uint8_t dst_addr[6];
		uint8_t src_addr[6];
		eth_field_type_t type_length;

		static const int ETH2_HEADER_LENGTH = 14;

		bool is_ethernet2() const;
		bool is_type_ipv4() const;
		uint8_t *get_eth2_sdu() const;
	} ether_header_t;

	/*
	 * IP protocol field
	 */
	enum ip_field_protocol_t : uint8_t {
		PROTO_ZERO = 0,
		ICMP = 1,
		TCP = 6,
		UDP = 17
	};

	/*
	 * IP header
	 */
	typedef struct {
		uint8_t ver_ihl;	// 4 bits version and 4 bits internet header length
		uint8_t tos;
		uint16_t total_length;
		uint16_t id;
		uint16_t flags_fo;	// 3 bits flags and 13 bits fragment-offset
		uint8_t ttl;
		ip_field_protocol_t protocol;
		uint16_t checksum;
		uint32_t src_addr;
		uint32_t dst_addr;

		static const int IP_MIN_HEADER_LENGTH = 20;

		uint8_t ihl() const;
		size_t header_length() const;
		uint8_t flags() const;
		bool flag_eb() const;	// Evil bit (reserved)
		bool flag_df() const;	// Do Not Fragment
		bool flag_mf() const;	// More Fragments
		size_t frag_offset() const;
		const char *protocol_str() const;
		uint8_t *get_sdu() const;
	} ip_header_t;

	/*
	 * UDP header 
	 */
	typedef struct {
		uint16_t src_port;
		uint16_t dst_port;
		uint16_t length;
		uint16_t checksum;

		static const int UDP_MIN_HEADER_LENGTH = 8;
	} udp_header_t;

	/*
	* TCP flags field
	*/
	typedef struct tcp_field_flags_t {
		uint8_t flags;

		tcp_field_flags_t();
		tcp_field_flags_t(uint8_t flags);
		bool fin() const;
		bool syn() const;
		bool rst() const;
		bool psh() const;
		bool ack() const;
		bool urg() const;	// Urgent
		bool ece() const;	// ECN Echo
		bool cwr() const;	// Congestion Window Reduced
	} tcp_field_flags_t;

	/*
	 * TCP header
	 */
	typedef struct {
		uint16_t src_port;
		uint16_t dst_port;
		uint32_t seq;
		uint32_t ack;
		uint8_t data_offset;  // 4 bits offset + 4 bits reserved
		tcp_field_flags_t flags;
		uint16_t window_size;
		uint16_t checksum;
		uint16_t urgent_p;

		static const int TCP_MIN_HEADER_LENGTH = 20;
	} tcp_header_t;
}