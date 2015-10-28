#pragma once

#include <map>
#include "net.h"
#include "Packet.h"
#include "TcpConnection.h"

namespace FeatureExtractor {
	using namespace std;

	class TcpConncetionReconstructor
	{
		class TcpConnectionKey {
			uint32_t src_ip;
			uint32_t dst_ip;
			uint16_t src_port;
			uint16_t dst_port;
		public:
			TcpConnectionKey();
			TcpConnectionKey(const Packet *packet);

			/*
			 * Returns key with src and dst swapped
			 */
			TcpConnectionKey get_reversed();

			bool operator<(const TcpConnectionKey& other) const; // Required for map<> key
		};

		typedef map<TcpConnectionKey, TcpConnection*> ConnectionMap;
		ConnectionMap connection_map;

	public:
		TcpConncetionReconstructor();
		~TcpConncetionReconstructor();


		TcpConnection *add_packet(const Packet *packet);
	};
}

