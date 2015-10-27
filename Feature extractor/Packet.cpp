#include "Packet.h"

namespace FeatureExtractor {
	Packet::Packet()
		: eth_type(TYPE_ZERO), ip_proto(PROTO_ZERO)
		, src_ip(0), dst_ip(0), src_port(0), dst_port(0)
		, tcp_flags(), length(0)
	{
		start_ts.tv_sec = 0;
		start_ts.tv_usec = 0;
	}


	Packet::~Packet()
	{
	}

	timeval Packet::get_start_ts()
	{
		return start_ts;
	}

	void Packet::set_start_ts(timeval start_ts)
	{
		this->start_ts = start_ts;
	}

	timeval Packet::get_end_ts()
	{
		// Return the start timestamp
		return start_ts;
	}

	bool Packet::is_eth2()
	{
		return eth2;
	}

	void Packet::set_eth2(bool is_eth2)
	{
		this->eth2 = is_eth2;
	}

	eth_field_type_t Packet::get_eth_type()
	{
		return eth_type;
	}

	void Packet::set_eth_type(eth_field_type_t eth_type){
		this->eth_type = eth_type;
	}

	ip_field_protocol_t Packet::get_ip_proto()
	{
		return ip_proto;
	}

	void Packet::set_ip_proto(ip_field_protocol_t ip_proto)
	{
		this->ip_proto = ip_proto;
	}

	uint32_t Packet::get_src_ip()
	{
		return src_ip;
	}

	void Packet::set_src_ip(uint32_t src_ip)
	{
		this->src_ip = src_ip;
	}

	uint32_t Packet::get_dst_ip()
	{
		return dst_ip;
	}

	void Packet::set_dst_ip(uint32_t dst_ip)
	{
		this->dst_ip = dst_ip;
	}

	uint16_t Packet::get_src_port()
	{
		return src_port;
	}

	void Packet::set_src_port(uint16_t src_port)
	{
		this->src_port = src_port;
	}

	uint16_t Packet::get_dst_port()
	{
		return dst_port;
	}

	void Packet::set_dst_port(uint16_t dst_port)
	{
		this->dst_port = dst_port;
	}

	tcp_field_flags_t Packet::get_tcp_flags()
	{
		return tcp_flags;
	}

	void Packet::set_tcp_flags(tcp_field_flags_t tcp_flags)
	{
		this->tcp_flags = tcp_flags;
	}

	size_t Packet::get_length()
	{
		return length;
	}

	void Packet::set_length(size_t length)
	{
		this->length = length;
	}

	uint16_t Packet::get_frame_count()
	{
		return 1;
	}

}