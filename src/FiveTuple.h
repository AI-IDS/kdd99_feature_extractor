#pragma once

#include "net.h"

namespace FeatureExtractor {
	/**
	 * 5-tuple identificator for conversation
	 * <IP protocol, source IP, source port, destination IP, destination port>
	 */
	class FiveTuple
	{
		ip_field_protocol_t ip_proto;
		uint32_t src_ip;
		uint32_t dst_ip;
		uint16_t src_port;
		uint16_t dst_port;

	public:
		FiveTuple();
		~FiveTuple();

		ip_field_protocol_t get_ip_proto() const;
		void set_ip_proto(ip_field_protocol_t ip_proto);

		uint32_t get_src_ip() const;
		void set_src_ip(uint32_t src_ip);

		uint32_t get_dst_ip() const;
		void set_dst_ip(uint32_t dst_ip);

		uint16_t get_src_port() const;
		void set_src_port(uint16_t src_port);

		uint16_t get_dst_port() const;
		void set_dst_port(uint16_t dst_port);

		/**
		 * Returns true if source endpoint (IP:port) is the same as destination
		 */
		bool land() const;

		/**
		 * Less than operator - can be used for map<> keyoperator 
		 * Operator '<' is applied to field in this order:
		 *  1. IP protocol
		 *  2. Source IP
		 *  3. Destination IP
		 *  4. Source port
		 *  5. Destionatio port
		 */
		bool operator<(const FiveTuple& other) const;

		/**
		 * Creates 5-tuple with swapped source and destionation (IPs, ports)
		 */
		FiveTuple get_reversed() const;

	};
}
