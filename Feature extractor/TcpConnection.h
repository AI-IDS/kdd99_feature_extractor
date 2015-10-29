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
		uint32_t src_packets;
		uint32_t dst_packets;
		uint32_t wrong_fragments;
		uint32_t urgent_packets;

		void update_tcp_state(const Packet *packet);
		bool is_in_final_state() const;
		static const char *state_to_str(TcpState state);

	public:
		TcpConnection();
		TcpConnection(const Packet *packet);
		~TcpConnection();

		uint32_t get_src_ip() const;
		uint32_t get_dst_ip() const;
		uint16_t get_src_port() const;
		uint16_t get_dst_port() const;

		TcpState get_state() const;

		struct timeval get_start_ts() const;
		struct timeval get_last_ts() const;
		uint32_t get_duration_ms() const;
		size_t get_src_bytes() const;
		size_t get_dst_bytes() const;
		uint32_t get_packets() const;
		uint32_t get_src_packets() const;
		uint32_t get_dst_packets() const;
		uint32_t get_wrong_fragments() const;
		uint32_t get_urgent_packets() const;
		bool land() const;

		/**
		 * Adds next packet to connection (without checking sequence number)
		 * Returns true if connection will get to final state
		 */
		bool add_packet(const Packet *packet);

		/**
		* Output the class values (e.g. for debuging purposes)
		*/
		void print() const;
		const char *get_state_str() const;

	};
}

