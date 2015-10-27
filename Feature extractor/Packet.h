#pragma once

#include "net.h"

namespace FeatureExtractor {
	class Packet
	{
		struct timeval start_ts;
		bool eth2;
		eth_field_type_t eth_type;
		ip_field_protocol_t ip_proto;
		uint32_t src_ip;
		uint32_t dst_ip;
		uint16_t src_port;
		uint16_t dst_port;
		tcp_field_flags_t tcp_flags;
		size_t length;

	public:
		Packet();
		~Packet();

		timeval get_start_ts();
		void set_start_ts(timeval start_ts);
		virtual timeval get_end_ts();

		bool is_eth2();
		void set_eth2(bool is_eth2);

		eth_field_type_t get_eth_type();
		void set_eth_type(eth_field_type_t eth_type);

		ip_field_protocol_t get_ip_proto();
		void set_ip_proto(ip_field_protocol_t ip_proto);

		uint32_t get_src_ip();
		void set_src_ip(uint32_t src_ip);

		uint32_t get_dst_ip();
		void set_dst_ip(uint32_t dst_ip);

		uint16_t get_src_port();
		void set_src_port(uint16_t src_port);

		uint16_t get_dst_port();
		void set_dst_port(uint16_t dst_port);

		tcp_field_flags_t get_tcp_flags();
		void set_tcp_flags(tcp_field_flags_t tcp_flags);

		virtual size_t get_length();
		virtual void set_length(size_t length);

		virtual uint16_t get_frame_count();

	};

}