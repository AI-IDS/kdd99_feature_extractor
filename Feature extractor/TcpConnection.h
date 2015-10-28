#pragma once

#include "net.h"

namespace FeatureExtractor {
	enum TcpState {
		INIT,
		S0,
		S1,
		ESTAB,
		S2,
		S3,
		SF,
		REJ,
		RSTOS0,
		RSTO,
		RSTR,
		SH,
		S4,
		RSTRH,
		SHR
	};

	class TcpConnection
	{
		struct timeval start_ts;
		struct timeval end_ts;
		uint32_t src_ip;
		uint32_t dst_ip;
		uint16_t src_port;
		uint16_t dst_port;
		TcpState state;
		size_t src_bytes;
		size_t dst_bytes;
		uint32_t wrong_fragments;
		uint32_t urgent_packets;

	public:
		TcpConnection();
		~TcpConnection();

		uint32_t get_src_ip() const;
		void set_src_ip(uint32_t src_ip);

		uint32_t get_dst_ip() const;
		void set_dst_ip(uint32_t dst_ip);

		uint16_t get_src_port() const;
		void set_src_port(uint16_t src_port);

		uint16_t get_dst_port() const;
		void set_dst_port(uint16_t dst_port);

		TcpState get_state() const;
		void set_state(TcpState state);

		size_t get_src_bytes() const;
		void set_src_bytes(size_t src_bytes);

		size_t get_dst_bytes() const;
		void set_dst_bytes(size_t dst_bytes);

		uint32_t get_wrong_fragments() const;
		void set_wrong_fragments(uint32_t wrong_fragments);

		uint32_t get_urgent_packets() const;
		void set_urgent_packets(uint32_t urgent_packets);

		bool land() const;

	};
}

