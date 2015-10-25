#pragma once

#include "net.h"

namespace FeatureExtractor {
	class Frame
	{
	public:
		struct timeval ts;
		size_t length;

		bool is_eth2;
		bool is_ipv4;
		bool is_icmp;
		bool is_tcp;
		bool is_udp;

		size_t size;
		
		// Layer3 - IP
		uint32_t src_ip;
		uint32_t dst_ip;
		uint16_t ip_id;
		ip_field_protocol_t ip_protocol;
		bool ip_flag_mf;
		uint16_t ip_frag_offset;

		// Layer 4 - TCP, UDP
		uint16_t src_port;
		uint16_t dst_port;
		bool tcp_flag_fin;
		bool tcp_flag_syn;
		bool tcp_flag_rst;
		bool tcp_flag_ack;
		bool tcp_flag_urg;

		Frame();
		~Frame();
		void print();

	};

}