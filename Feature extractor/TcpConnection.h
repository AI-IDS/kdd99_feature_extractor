#pragma once

#include "net.h"
#include "Packet.h"

namespace FeatureExtractor {
	enum TcpState {
		INIT,
		S0,
		S1,
		S2,
		S3,
		SF,
		REJ,
		RSTOS0,
		RSTO,
		RSTR,
		SH,
		RSTRH,
		SHR,
		OTH,

		// Internal states
		ESTAB,
		S4,
		S2F,
		S3F
	};

	class TcpConnection
	{
		uint32_t src_ip;
		uint32_t dst_ip;
		uint16_t src_port;
		uint16_t dst_port;

		TcpState state;

		struct timeval start_ts;
		struct timeval last_ts;
		size_t src_bytes;
		size_t dst_bytes;
		uint32_t packets;
		uint32_t wrong_fragments;
		uint32_t urgent_packets;

		void update_state(const Packet *packet);
		bool is_in_final_state() const;

	public:
		TcpConnection();
		TcpConnection(const Packet *packet);
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
		void add_src_bytes(size_t src_bytes);

		size_t get_dst_bytes() const;
		void set_dst_bytes(size_t dst_bytes);
		void add_dst_bytes(size_t dst_bytes);

		uint32_t get_packets() const;
		void set_packets(uint32_t packets);
		void inc_packets();

		uint32_t get_wrong_fragments() const;
		void set_wrong_fragments(uint32_t wrong_fragments);
		void inc_wrong_fragments();

		uint32_t get_urgent_packets() const;
		void set_urgent_packets(uint32_t urgent_packets);
		void inc_urgent_packets();

		bool land() const;

		/*
		 * Adds next packet to connection (without checking sequence number)
		 * Returns true if connection will get to final state
		 */
		bool add_packet(const Packet *packet);

	};
}

