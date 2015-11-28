#pragma once

#include "Packet.h"

namespace FeatureExtractor {
	class IpFragment :
		public Packet
	{
		uint16_t ip_id;
		bool ip_flag_mf;
		uint16_t ip_frag_offset;
		size_t ip_payload_length;

	public:
		IpFragment();
		~IpFragment();

		uint16_t get_ip_id() const;
		void set_ip_id(uint16_t ip_id);

		bool get_ip_flag_mf() const;
		void set_ip_flag_mf(bool ip_flag_mf);

		uint16_t get_ip_frag_offset() const;
		void set_ip_frag_offset(uint16_t ip_frag_offset);

		size_t get_ip_payload_length() const;
		void set_ip_payload_length(size_t ip_payload_length);

		/**
		 * Output the class values (e.g. for debuging purposes)
		 * overriden
		 */
		void print() const;
	};
}
