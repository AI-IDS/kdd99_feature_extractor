#include <sstream>
#include <iostream>
#include "Packet.h"

namespace FeatureExtractor {
	using namespace std;

	Packet::Packet()
		: start_ts(), eth2(false), eth_type(TYPE_ZERO), five_tuple()
		, tcp_flags(), icmp_type(ECHOREPLY), icmp_code(0)
		, length(0)
	{
	}


	Packet::~Packet()
	{
	}

	Timestamp Packet::get_start_ts() const
	{
		return start_ts;
	}

	void Packet::set_start_ts(const Timestamp &start_ts)
	{
		this->start_ts = start_ts;
	}

	Timestamp Packet::get_end_ts() const
	{
		// Return the start timestamp by default
		return start_ts;
	}

	bool Packet::is_eth2() const
	{
		return eth2;
	}

	void Packet::set_eth2(bool is_eth2)
	{
		this->eth2 = is_eth2;
	}

	eth_field_type_t Packet::get_eth_type() const
	{
		return eth_type;
	}

	void Packet::set_eth_type(eth_field_type_t eth_type){
		this->eth_type = eth_type;
	}

	FiveTuple Packet::get_five_tuple() const
	{
		return five_tuple;
	}
	void Packet::set_five_tuple(const FiveTuple &five_tuple)
	{
		this->five_tuple = five_tuple;
	}

	ip_field_protocol_t Packet::get_ip_proto() const
	{
		return five_tuple.get_ip_proto();
	}

	void Packet::set_ip_proto(ip_field_protocol_t ip_proto)
	{
		this->five_tuple.set_ip_proto(ip_proto);
	}

	uint32_t Packet::get_src_ip() const
	{
		return five_tuple.get_src_ip();
	}

	void Packet::set_src_ip(uint32_t src_ip)
	{
		this->five_tuple.set_src_ip(src_ip);
	}

	uint32_t Packet::get_dst_ip() const
	{
		return five_tuple.get_dst_ip();
	}

	void Packet::set_dst_ip(uint32_t dst_ip)
	{
		this->five_tuple.set_dst_ip(dst_ip);
	}

	uint16_t Packet::get_src_port() const
	{
		return five_tuple.get_src_port();
	}

	void Packet::set_src_port(uint16_t src_port)
	{
		this->five_tuple.set_src_port(src_port);
	}

	uint16_t Packet::get_dst_port() const
	{
		return five_tuple.get_dst_port();
	}

	void Packet::set_dst_port(uint16_t dst_port)
	{
		this->five_tuple.set_dst_port(dst_port);
	}

	tcp_field_flags_t Packet::get_tcp_flags() const
	{
		return tcp_flags;
	}

	void Packet::set_tcp_flags(tcp_field_flags_t tcp_flags)
	{
		this->tcp_flags = tcp_flags;
	}

	icmp_field_type_t Packet::get_icmp_type() const
	{
		return icmp_type;
	}
	void Packet::set_icmp_type(icmp_field_type_t icmp_type)
	{
		this->icmp_type = icmp_type;
	}

	uint8_t Packet::get_icmp_code() const
	{
		return icmp_code;
	}
	void Packet::set_icmp_code(uint8_t icmp_code)
	{
		this->icmp_code = icmp_code;
	}

	size_t Packet::get_length() const
	{
		return length;
	}

	void Packet::set_length(size_t length)
	{
		this->length = length;
	}

	uint16_t Packet::get_frame_count() const
	{
		// By default packet consists of 1 frame
		return 1;
	}

// Allow using localtime instead of localtime_s 
#ifdef _MSC_VER
	#pragma warning(disable:4996)
#endif
	void Packet::print_human() const
	{
		// TODO: WTF ugly code, just for debugging, mal si branic..
		stringstream ss;

		struct tm *ltime;
		//struct tm timeinfo;
		char timestr[16];
		time_t local_tv_sec;
		//local_tv_sec = start_ts.get_secs();
		ltime = localtime(&local_tv_sec);
		//localtime_s(&timeinfo, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		//strftime(timestr, sizeof timestr, "%H:%M:%S", &timeinfo);
		ss << timestr;

		ss << (is_eth2() ? " ETHERNET II" : " NON-ETHERNET");
		if (!is_eth2()) {
			cout << endl << ss.str() << endl;
			return;
		}
		ss << (eth_type == IPV4 ? " > IP" : " > NON-IP");
		if (eth_type != IPV4) {
			ss << "(0x" << hex << eth_type << dec << ")";
			cout << endl << ss.str() << endl;
			return;
		}

		if (get_ip_proto() == ICMP) {
			ss << " > ICMP " << endl;
		}
		else if (get_ip_proto() == TCP) {
			ss << " > TCP " << endl;
		}
		else if (get_ip_proto() == UDP) {
			ss << " > UDP " << endl;
		}
		else {
			ss << " > Other(0x" << hex << get_ip_proto() << dec << ")" << endl;
		}

		// Cast ips to arrays of octets
		uint32_t src_ip = get_src_ip();
		uint32_t dst_ip = get_dst_ip();
		uint8_t *sip = (uint8_t *)&src_ip;
		uint8_t *dip = (uint8_t *)&dst_ip;

		if (get_ip_proto() != TCP && get_ip_proto() != UDP) {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3];
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3];
			ss << " length=" << get_length();
			if (get_frame_count() > 1)
				ss << " frames=" << get_frame_count();
			ss << endl;
			if (get_ip_proto() == ICMP) {
				ss << "  icmp_type=" << icmp_type << " icmp_code=" << icmp_code << endl;
			}
		}
		else {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3] << ":" << get_src_port();
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3] << ":" << get_dst_port();
			ss << " length=" << get_length();
			if (get_frame_count() > 1)
				ss << " frames=" << get_frame_count();
			ss << endl;

			if (get_ip_proto() == TCP) {
				ss << "  Flags(0x" << hex << (int) tcp_flags.flags << dec << "): ";
				ss << (tcp_flags.fin() ? "F" : "");
				ss << (tcp_flags.syn() ? "S" : "");
				ss << (tcp_flags.rst() ? "R" : "");
				ss << (tcp_flags.ack() ? "A" : "");
				ss << (tcp_flags.urg() ? "U" : "");
				ss << endl;
			}
		}

		cout << endl << ss.str();
	}

}