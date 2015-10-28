#include "TcpConnection.h"


namespace FeatureExtractor {

	TcpConnection::TcpConnection()
		: src_ip(0), dst_ip(0), src_port(0), dst_port(0)
		, state(INIT), src_bytes(0), dst_bytes(0)
		, wrong_fragments(0), urgent_packets(0)
	{
		start_ts.tv_sec = 0;
		start_ts.tv_usec = 0;
		end_ts.tv_sec = 0;
		end_ts.tv_usec = 0;
	}


	TcpConnection::~TcpConnection()
	{
	}

	uint32_t TcpConnection::get_src_ip() const
	{
		return src_ip;
	}

	void TcpConnection::set_src_ip(uint32_t src_ip)
	{
		this->src_ip = src_ip;
	}

	uint32_t TcpConnection::get_dst_ip() const
	{
		return dst_ip;
	}

	void TcpConnection::set_dst_ip(uint32_t dst_ip)
	{
		this->dst_ip = dst_ip;
	}

	uint16_t TcpConnection::get_src_port() const
	{
		return src_port;
	}

	void TcpConnection::set_src_port(uint16_t src_port)
	{
		this->src_port = src_port;
	}

	uint16_t TcpConnection::get_dst_port() const
	{
		return dst_port;
	}

	void TcpConnection::set_dst_port(uint16_t dst_port)
	{
		this->dst_port = dst_port;
	}


	TcpState TcpConnection::get_state() const
	{
		return state;
	}

	void TcpConnection::set_state(TcpState state)
	{
		this->state = state;
	}

	size_t TcpConnection::get_src_bytes() const
	{
		return src_bytes;
	}

	void TcpConnection::set_src_bytes(size_t src_bytes)
	{
		this->src_bytes = src_bytes;
	}

	size_t TcpConnection::get_dst_bytes() const
	{
		return dst_bytes;
	}

	void TcpConnection::set_dst_bytes(size_t dst_bytes)
	{
		this->dst_bytes = dst_bytes;
	}

	uint32_t TcpConnection::get_wrong_fragments() const
	{
		return wrong_fragments;
	}

	void TcpConnection::set_wrong_fragments(uint32_t wrong_fragments)
	{
		this->wrong_fragments = wrong_fragments;
	}

	uint32_t TcpConnection::get_urgent_packets() const
	{
		return urgent_packets;
	}

	void TcpConnection::set_urgent_packets(uint32_t urgent_packets)
	{
		this->urgent_packets = urgent_packets;
	}


	bool TcpConnection::land() const
	{
		return (src_ip == dst_ip && src_port == dst_port);
	}
}
