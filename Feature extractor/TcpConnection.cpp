#include <sstream>
#include <iostream>
#include "TcpConnection.h"


namespace FeatureExtractor {
	using namespace std;

	TcpConnection::TcpConnection()
		: src_ip(0), dst_ip(0), src_port(0), dst_port(0)
		, state(INIT), src_bytes(0), dst_bytes(0)
		, packets(0), wrong_fragments(0), urgent_packets(0)
	{
		start_ts.tv_sec = 0;
		start_ts.tv_usec = 0;
		last_ts.tv_sec = 0;
		last_ts.tv_usec = 0;
	}

	TcpConnection::TcpConnection(const Packet *packet)
		: state(INIT), src_bytes(0), dst_bytes(0)
		, packets(0), wrong_fragments(0), urgent_packets(0)
	{
		start_ts.tv_sec = 0;
		start_ts.tv_usec = 0;
		last_ts.tv_sec = 0;
		last_ts.tv_usec = 0;

		src_ip = packet->get_src_ip();
		dst_ip = packet->get_dst_ip();
		src_port = packet->get_src_port();
		dst_port = packet->get_dst_port();
	}


	TcpConnection::~TcpConnection()
	{
	}

	uint32_t TcpConnection::get_src_ip() const
	{
		return src_ip;
	}

	uint32_t TcpConnection::get_dst_ip() const
	{
		return dst_ip;
	}

	uint16_t TcpConnection::get_src_port() const
	{
		return src_port;
	}

	uint16_t TcpConnection::get_dst_port() const
	{
		return dst_port;
	}


	TcpState TcpConnection::get_state() const
	{
		// Replace internal states
		switch (state) {
		case ESTAB:
			return S1;
			break;

		case S4:
			return OTH;
			break;

		case S2F:
			return S2;
			break;

		case S3F:
			return S3;
			break;

		default:
			return state;
			break;
		}
		return state;
	}

	struct timeval TcpConnection::get_start_ts() const
	{
		return start_ts;
	}

	struct timeval TcpConnection::get_last_ts() const
	{
		return last_ts;
	}

	uint32_t TcpConnection::get_duration_ms() const
	{
		return ((last_ts.tv_sec - start_ts.tv_sec) * 1000) +
			((last_ts.tv_usec - start_ts.tv_usec) / 1000);
	}

	size_t TcpConnection::get_src_bytes() const
	{
		return src_bytes;
	}

	size_t TcpConnection::get_dst_bytes() const
	{
		return dst_bytes;
	}

	uint32_t TcpConnection::get_packets() const
	{
		return packets;
	}

	uint32_t TcpConnection::get_wrong_fragments() const
	{
		return wrong_fragments;
	}

	uint32_t TcpConnection::get_urgent_packets() const
	{
		return urgent_packets;
	}


	bool TcpConnection::land() const
	{
		return (src_ip == dst_ip && src_port == dst_port);
	}

	bool TcpConnection::add_packet(const Packet *packet)
	{
		// Timestamps
		if (packets == 0)
			start_ts = packet->get_start_ts();
		last_ts = packet->get_end_ts();
		
		// Add byte counts for correct direction
		if (packet->get_src_ip() == src_ip) {
			src_bytes += packet->get_length();
		}
		else {
			dst_bytes += packet->get_length();
		}

		// Packet counts
		//TODO: wrong_fragments
		packets++;
		if (packet->get_tcp_flags().urg())
			urgent_packets++;

		// Make state transitions according to packet if TCP,
		// all other protocols will get to finalstate SH directly
		if (packet->get_ip_proto() == TCP)
			update_tcp_state(packet);
		else
			state = SH;

		// TODO: make universal connection

		return is_in_final_state();
	}

	void TcpConnection::update_tcp_state(const Packet *packet)
	{
		// Is the packet from originator or responder?
		bool originator = (packet->get_src_ip() == src_ip);

		tcp_field_flags_t f = packet->get_tcp_flags();

		switch (state) {
		case INIT:
			if (f.syn() && f.ack())
				state = S4;
			else if (f.syn())
				state = S1;
			else
				state = OTH;	
			break;

		case S0:
			if (originator) {
				if (f.rst())
					state = RSTOS0;
				else if (f.fin())
					state = SH;
			}
			else { // from responder
				if (f.rst())
					state = REJ;
				else if (f.syn() && f.ack())
					state = S1;
			}
			break;

		case S4:
			if (originator) {
				if (f.rst())
					state = RSTRH;
				else if (f.fin())
					state = SHR;
			}
			break;

		case S1:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.ack())
					state = ESTAB;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case ESTAB:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.fin())
					state = S2;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.fin())
					state = S3;
			}
			break;

		case S2:
			if (originator) {
				if (f.rst())
					state = RSTO;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.fin())
					state = S2F;
			}
			break;

		case S3:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.fin())
					state = S3F;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case S2F:
			if (originator) {
				if (f.rst())
					state = RSTO;
				else if (f.ack())
					state = SF;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
			}
			break;

		case S3F:
			if (originator) {
				if (f.rst())
					state = RSTO;
			}
			else { // responder
				if (f.rst())
					state = RSTR;
				else if (f.ack())
					state = SF;
			}
			break;

		default:
			break;

		}
	}

	bool TcpConnection::is_in_final_state() const
	{
		// Get state with internal states replaced
		switch (this->get_state())
		{
		case INIT:
		case S0:
		case S1:
		case S4:
		case ESTAB:
		case S2:
		case S3:
			return false;
			break;

		default:
			return true;
			break;
		}
		return true;
	}

	void TcpConnection::print() const
	{
		stringstream ss;

		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		local_tv_sec = get_start_ts().tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		ss << "CONNECTION " << timestr;
		ss << " duration=" << get_duration_ms() << "ms" << endl;

		// Cast ips to arrays of octets
		uint8_t *sip = (uint8_t *)&src_ip;
		uint8_t *dip = (uint8_t *)&dst_ip;

		ss << "  src=" << (int)sip[0] << "." << (int)sip[1] << "." << (int)sip[2] << "." << (int)sip[3] << ":" << get_src_port();
		ss << " dst=" << (int)dip[0] << "." << (int)dip[1] << "." << (int)dip[2] << "." << (int)dip[3] << ":" << get_dst_port() << endl;
		ss << "  src_bytes=" << src_bytes << " dst_bytes=" << dst_bytes << " land=" << land() << endl;
		ss << "  pkts=" << packets << " wrong_frags=" << wrong_fragments << " urg_pkts=" << urgent_packets;
		ss << "  state=" << get_state_str() << " internal_state=" << state_to_str(state) << endl;
		ss << endl;

	}

	const char *TcpConnection::get_state_str() const 
	{
		return state_to_str(get_state());
	}
		
	const char *TcpConnection::state_to_str(TcpState state)
	{
		switch (state) {
		case INIT: return "INIT"; break;
		case S0: return "S0"; break;
		case S1: return "S1"; break;
		case S2: return "S2"; break;
		case S3: return "S3"; break;
		case SF: return "SF"; break;
		case REJ: return "REJ"; break;
		case RSTOS0: return "RSTOS0"; break;
		case RSTO: return "RSTO"; break;
		case RSTR: return "RSTR"; break;
		case SH: return "SH"; break;
		case RSTRH: return "RSTRH"; break;
		case SHR: return "SHR"; break;
		case OTH: return "OTH"; break;
		case ESTAB: return "ESTAB"; break;
		case S4: return "S4"; break;
		case S2F: return "S2F"; break;
		case S3F: return "S3F"; break;
		}

		return "UNKNOWN";
	}
}
