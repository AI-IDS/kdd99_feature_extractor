#include "FiveTuple.h"

namespace FeatureExtractor {

	FiveTuple::FiveTuple()
		: ip_proto(PROTO_ZERO), src_ip(0), dst_ip(0), src_port(0), dst_port(0)
	{
	}


	FiveTuple::~FiveTuple()
	{
	}

	ip_field_protocol_t FiveTuple::get_ip_proto() const
	{
		return ip_proto;
	}

	void FiveTuple::set_ip_proto(ip_field_protocol_t ip_proto)
	{
		this->ip_proto = ip_proto;
	}

	uint32_t FiveTuple::get_src_ip() const
	{
		return src_ip;
	}

	void FiveTuple::set_src_ip(uint32_t src_ip)
	{
		this->src_ip = src_ip;
	}

	uint32_t FiveTuple::get_dst_ip() const
	{
		return dst_ip;
	}

	void FiveTuple::set_dst_ip(uint32_t dst_ip)
	{
		this->dst_ip = dst_ip;
	}

	uint16_t FiveTuple::get_src_port() const
	{
		return src_port;
	}

	void FiveTuple::set_src_port(uint16_t src_port)
	{
		this->src_port = src_port;
	}

	uint16_t FiveTuple::get_dst_port() const
	{
		return dst_port;
	}

	void FiveTuple::set_dst_port(uint16_t dst_port)
	{
		this->dst_port = dst_port;
	}

	bool FiveTuple::land() const
	{
		return (src_ip == dst_ip && src_port == dst_port);
	}

	bool FiveTuple::operator<(const FiveTuple& other) const
	{
		if (ip_proto < other.ip_proto)
			return true;
		if (ip_proto > other.ip_proto)
			return false;

		// IP protocols are same
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

	FiveTuple FiveTuple::get_reversed() const
	{
		FiveTuple tuple;
		tuple.ip_proto = this->ip_proto;
		tuple.src_ip = this->dst_ip;
		tuple.dst_ip = this->src_ip;
		tuple.src_port = this->dst_port;
		tuple.dst_port = this->src_port;

		return tuple;
	}
}
