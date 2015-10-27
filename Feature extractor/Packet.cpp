#include <sstream>
#include <iostream>
#include "Packet.h"

namespace FeatureExtractor {
	using namespace std;

	Packet::Packet()
		: eth2(false), eth_type(TYPE_ZERO), ip_proto(PROTO_ZERO)
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
		// By default packet consists of 1 frame
		return 1;
	}

	void Packet::print()
	{
		stringstream ss;

		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		local_tv_sec = get_start_ts().tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		ss << timestr;

		ss << (is_eth2() ? " ETHERNET II" : " NON-ETHERNET");
		if (!is_eth2()) {
			cout << ss.str() << endl;
			return;
		}
		ss << (eth_type == IPV4 ? " > IP" : " > NON-IP");
		if (eth_type != IPV4) {
			ss << "(0x" << hex << eth_type << dec << ")";
			cout << ss.str() << endl;
			return;
		}

		if (ip_proto == ICMP) {
			ss << " > ICMP " << endl;
		}
		else if (ip_proto == TCP) {
			ss << " > TCP " << endl;
		}
		else if (ip_proto == UDP) {
			ss << " > UDP " << endl;
		}
		else {
			ss << " > Other(0x" << hex << ip_proto << dec << ")" << endl;
		}

		// Cast ips to arrays of octets
		uint8_t *sip = (uint8_t *)&src_ip;
		uint8_t *dip = (uint8_t *)&dst_ip;

		if (ip_proto != TCP && ip_proto != UDP) {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3];
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3];
			ss << " length=" << get_length();
			ss << " frames=" << get_frame_count() << endl;
		}
		else {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3] << ":" << get_src_port();
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3] << ":" << get_dst_port();
			ss << " length=" << get_length();
			ss << " frames=" << get_frame_count() << endl;

			if (ip_proto == TCP) {
				ss << "  Flags: ";
				ss << (tcp_flags.fin() ? "F" : "");
				ss << (tcp_flags.syn() ? "S" : "");
				ss << (tcp_flags.rst() ? "R" : "");
				ss << (tcp_flags.ack() ? "A" : "");
				ss << (tcp_flags.urg() ? "U" : "");
			}
		}

		cout << endl << ss.str();
	}

}