#include "TcpConnection.h"


namespace FeatureExtractor {

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

	void TcpConnection::add_src_bytes(size_t src_bytes)
	{
		this->src_bytes += src_bytes;
	}

	size_t TcpConnection::get_dst_bytes() const
	{
		return dst_bytes;
	}

	void TcpConnection::set_dst_bytes(size_t dst_bytes)
	{
		this->dst_bytes = dst_bytes;
	}

	void TcpConnection::add_dst_bytes(size_t dst_bytes)
	{
		this->dst_bytes += dst_bytes;
	}

	uint32_t TcpConnection::get_packets() const
	{
		return packets;
	}

	void TcpConnection::set_packets(uint32_t packets)
	{
		this->packets = packets;
	}

	void TcpConnection::inc_packets()
	{
		this->packets++;
	}

	uint32_t TcpConnection::get_wrong_fragments() const
	{
		return wrong_fragments;
	}

	void TcpConnection::set_wrong_fragments(uint32_t wrong_fragments)
	{
		this->wrong_fragments = wrong_fragments;
	}

	void TcpConnection::inc_wrong_fragments()
	{
		this->wrong_fragments++;
	}

	uint32_t TcpConnection::get_urgent_packets() const
	{
		return urgent_packets;
	}

	void TcpConnection::set_urgent_packets(uint32_t urgent_packets)
	{
		this->urgent_packets = urgent_packets;
	}

	void TcpConnection::inc_urgent_packets()
	{
		this->urgent_packets++;
	}

	// TODO: remove watafak above

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

		update_state(packet);	
	}

	void TcpConnection::update_state(const Packet *packet)
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

}
