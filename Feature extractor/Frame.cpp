#include <sstream>
#include <iostream>
#include "Frame.h"



namespace FeatureExtractor {

	using namespace std;

	Frame::Frame()
		: length(0)
		, is_eth2(false), is_ipv4(false), is_icmp(false), is_tcp(false), is_udp(false)
		, src_ip(0), dst_ip(0)
		, ip_id(0), ip_protocol(PROTO_ZERO), ip_flag_mf(false), ip_frag_offset(0), ip_payload_length(0)
		, src_port(0), dst_port(0)
		, tcp_flag_syn(false), tcp_flag_ack(false), tcp_flag_rst(false), tcp_flag_urg(false)
	{

	}


	Frame::~Frame()
	{
	}

	void Frame::print()
	{
		stringstream ss;

		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		local_tv_sec = ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		ss << timestr;

		ss << (is_eth2 ? " ETHERNET II" : " NON-ETHERNET");
		if (!is_eth2) {
			cout << ss.str() << endl;
			return;
		}
		ss << (is_ipv4 ? " > IP" : " > NON-IP");
		if (!is_ipv4) {
			cout << ss.str() << endl;
			return;
		}

		if (is_icmp) {
			ss << " > ICMP " << endl;
		}
		else if (is_tcp) {
			ss << " > TCP " << endl;
		}
		else if (is_udp) {
			ss << " > UDP " << endl;
		}
		else {
			ss << " > Other " << endl;
		}
		ss << "  ip.mf=" << ip_flag_mf << ", ip.offset=" << ip_frag_offset << ", ip.id=" << hex << ip_id << dec << endl;

		// Cast ips to array of
		uint8_t *sip = (uint8_t *) &src_ip;
		uint8_t *dip = (uint8_t *) &dst_ip;

		if (!is_tcp && !is_udp) {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3];
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3];
			ss << " length=" << length << endl;
		}
		else {
			ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3] << ":" << src_port;
			ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3] << ":" << dst_port;
			ss << " length=" << length << endl;
			if (is_tcp) {
				ss << "  Flags: ";
				ss << (tcp_flag_fin ? "F" : "");
				ss << (tcp_flag_syn ? "S" : "");
				ss << (tcp_flag_rst ? "R" : "");
				ss << (tcp_flag_ack ? "A" : "");
				ss << (tcp_flag_urg ? "U" : "");
			}
		}
 

		cout << ss.str() << endl;
	}
}