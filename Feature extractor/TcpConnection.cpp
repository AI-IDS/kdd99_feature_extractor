#include <sstream>
#include <iostream>
#include "TcpConnection.h"


namespace FeatureExtractor {
	using namespace std;

	TcpConnection::TcpConnection()
		: Conversation()
	{
	}

	TcpConnection::TcpConnection(const FiveTuple *tuple)
		: Conversation(tuple)
	{
	}

	TcpConnection::TcpConnection(const Packet *packet)
		: Conversation(packet)
	{
	}


	TcpConnection::~TcpConnection()
	{
	}

	void TcpConnection::update_state(const Packet *packet)
	{
		// Is the packet from originator or responder?
		bool originator = (packet->get_src_ip() == five_tuple.get_src_ip());

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
