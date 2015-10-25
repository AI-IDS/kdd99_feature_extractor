#pragma once

#include <stdint.h>
#ifdef _WIN32
#include <winsock.h>
#endif // _WIN32
/*
 * Inspired by http://stackoverflow.com/a/16523804/3503528
 */

namespace FeatureExtractor {
	/* 
	 * Ethernet header 
	 */
	enum eth_field_type : uint16_t {
		MIN_ETH2 = 0x600,
		IPV4 = 0x800
	};
	typedef struct {
		uint8_t dst_addr[6];
		uint8_t src_addr[6];
		eth_field_type type_length;

		static const int ETH2_HEADER_LENGTH = 14;

		bool is_ethernet2() const;
		bool is_type_ipv4() const;
		uint8_t *get_eth2_sdu() const;
	} ether_header_t;

	/*
	 * IP header 
	 */
	enum ip_field_protocol : uint8_t {
		ICMP = 1,
		TCP = 6,
		UDP = 17
	};
	typedef struct {
		uint8_t ver_ihl;	// 4 bits version and 4 bits internet header length
		uint8_t tos;
		uint16_t total_length;
		uint16_t id;
		uint16_t flags_fo;	// 3 bits flags and 13 bits fragment-offset
		uint8_t ttl;
		ip_field_protocol protocol;
		uint16_t checksum;
		uint32_t src_addr;
		uint32_t dst_addr;

		uint8_t ihl() const;
		size_t header_length() const;
		uint8_t flags() const;
		bool flag_eb() const;	// Evil bit
		bool flag_df() const;	// Do Not Fragment
		bool flag_mf() const;	// More Fragments
		uint16_t frag_offset() const;
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
	} udp_header_t;

	/*
	 * TCP header
	 */
	typedef struct {
		uint16_t src_port;
		uint16_t dst_port;
		uint32_t seq;
		uint32_t ack;
		uint8_t data_offset;  // 4 bits
		uint8_t flags;
		uint16_t window_size;
		uint16_t checksum;
		uint16_t urgent_p;
	} tcp_header_t;
}