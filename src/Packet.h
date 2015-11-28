#pragma once

#include "net.h"
#include "Timestamp.h"
#include "FiveTuple.h"

namespace FeatureExtractor {
	/**
	 * Abstract Packet
	 */
	class Packet
	{
		Timestamp start_ts;
		bool eth2;
		eth_field_type_t eth_type;

		// <IP protocol, source IP, source port, destination IP, destination port>
		FiveTuple five_tuple;

		tcp_field_flags_t tcp_flags;
		icmp_field_type_t icmp_type;
		uint8_t icmp_code;
		size_t length;

	public:
		Packet();
		virtual ~Packet();

		Timestamp get_start_ts() const;
		void set_start_ts(const Timestamp &start_ts);
		virtual Timestamp get_end_ts() const;

		bool is_eth2() const;
		void set_eth2(bool is_eth2);

		eth_field_type_t get_eth_type() const;
		void set_eth_type(eth_field_type_t eth_type);

		ip_field_protocol_t get_ip_proto() const;
		void set_ip_proto(ip_field_protocol_t ip_proto);

		FiveTuple get_five_tuple() const;
		void set_five_tuple(const FiveTuple &five_tuple);

		uint32_t get_src_ip() const;
		void set_src_ip(uint32_t src_ip);

		uint32_t get_dst_ip() const;
		void set_dst_ip(uint32_t dst_ip);

		uint16_t get_src_port() const;
		void set_src_port(uint16_t src_port);

		uint16_t get_dst_port() const;
		void set_dst_port(uint16_t dst_port);

		tcp_field_flags_t get_tcp_flags() const;
		void set_tcp_flags(tcp_field_flags_t tcp_flags);

		icmp_field_type_t get_icmp_type() const;
		void set_icmp_type(icmp_field_type_t icmp_type);

		uint8_t get_icmp_code() const;
		void set_icmp_code(uint8_t icmp_code);

		virtual size_t get_length() const;
		virtual void set_length(size_t length);

		virtual uint16_t get_frame_count() const;

		/**
		 * Output the class values (e.g. for debuging purposes)
		 */
		virtual void print_human() const;

	};

}