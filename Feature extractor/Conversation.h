#pragma once

#include "net.h"
#include "Packet.h"
#include "FiveTuple.h"
#include "Timestamp.h"

namespace FeatureExtractor {

	/**
	* Conversatiov states 
	*	- INIT & SF for all protocols except TCP
	*	- other states specific to TCP
	* Description from https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html
	*/
	enum ConversationState {
		// General states
		INIT,		// Nothing happened yet.
		SF,			// Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.

		// TCP specific
		S0,			// Connection attempt seen, no reply.
		S1,			// Connection established, not terminated.
		S2,			// Connection established and close attempt by originator seen (but no reply from responder).
		S3,			// Connection established and close attempt by responder seen (but no reply from originator).
		SF,			// Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
		REJ,		// Connection attempt rejected.
		RSTOS0,		// Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
		RSTO,		// Connection established, originator aborted (sent a RST).
		RSTR,		// Established, responder aborted.
		SH,			// Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
		RSTRH,		// Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
		SHR,		// Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
		OTH,		// No SYN seen, just midstream traffic (a “partial connection” that was not later closed).

		// Internal states (TCP-specific)
		ESTAB,		// Established - ACK send by originator in S1 state; externally represented as S1
		S4,			// SYN ACK seen - State between INIT and (RSTRH or SHR); externally represented as 
		S2F,		// FIN send by responder in state S2 - waiting for final ACK; externally represented as S2
		S3F			// FIN send by originator in state S3 - waiting for final ACK; externally represented as S3
	};

	/**
	 * Abstract Conversation (incorrectly called connection)
	 */
	class Conversation
	{
		FiveTuple five_tuple;
		ConversationState state;

		Timestamp start_ts;
		Timestamp last_ts;





	public:
		Conversation();
		Conversation(const FiveTuple *tuple);
		Conversation(const Packet *packet);
		~Conversation();
	};
}
