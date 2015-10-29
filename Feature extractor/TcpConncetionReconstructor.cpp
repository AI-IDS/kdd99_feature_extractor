#include "TcpConncetionReconstructor.h"

namespace FeatureExtractor {

	TcpConncetionReconstructor::TcpConncetionReconstructor()
	{
	}


	TcpConncetionReconstructor::~TcpConncetionReconstructor()
	{
	}

	TcpConncetionReconstructor::TcpConnectionKey::TcpConnectionKey()
		: src_ip(0), dst_ip(0), src_port(0), dst_port(0)
	{}
	TcpConncetionReconstructor::TcpConnectionKey::TcpConnectionKey(const Packet *packet)
	{
		src_ip = packet->get_src_ip();
		dst_ip = packet->get_dst_ip();
		src_port = packet->get_src_port();
		dst_port = packet->get_dst_port();
	}

	bool TcpConncetionReconstructor::TcpConnectionKey::operator<(const TcpConnectionKey& other) const
	{
		if (src_ip < other.src_ip)
			return true;
		if (src_ip > other.src_ip)
			return false;

		// src IPs are equal
		if (dst_ip < other.dst_ip)
			return true;
		if (dst_ip > other.dst_ip)
			return false;

		// dst IPs are equal
		if (src_port < other.src_port)
			return true;
		if (src_port > other.src_port)
			return false;

		// src ports are equal
		return (dst_port < other.dst_port);
	}
	TcpConncetionReconstructor::TcpConnectionKey TcpConncetionReconstructor::TcpConnectionKey::get_reversed()
	{
		TcpConnectionKey key;
		key.src_ip = this->dst_ip;
		key.dst_ip = this->src_ip;
		key.src_port = this->dst_port;
		key.dst_port = this->src_port;

		return key;
	}


	TcpConnection *TcpConncetionReconstructor::add_packet(const Packet *packet)
	{
		TcpConnectionKey key(packet);
		TcpConnection *conn = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove finished connection from map
		// - if connection not found, try with swapped src & dst (opposite direction)
		ConnectionMap::iterator it = conn_map.lower_bound(key);
		if (it == conn_map.end() || (conn_map.key_comp()(key, it->first))) {
			// If not found, try with opposite direction
			it = conn_map.lower_bound(key.get_reversed());
		}

		if (it != conn_map.end() && !(conn_map.key_comp()(key, it->first)))
		{
			// Key (connection) already exists
			conn = it->second;
		}
		else {
			// The key (connection) does not exist in the map
			conn = new TcpConnection(packet);
			it = conn_map.insert(it, ConnectionMap::value_type(key, conn));
		}

		// Pass new packet to connection
		bool is_finished = conn->add_packet(packet);

		// If connection is in final state, remove it from map & return it
		if (is_finished) {
			conn_map.erase(it);	
			return conn;
		}

		return nullptr;
	}
}