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
	protected:
		FiveTuple five_tuple;
		ConversationState state;

		Timestamp start_ts;
		Timestamp last_ts;

		size_t src_bytes;
		size_t dst_bytes;
		uint32_t packets;
		uint32_t src_packets;
		uint32_t dst_packets;
		uint32_t wrong_fragments;
		uint32_t urgent_packets;

		virtual void update_state(const Packet *packet);
		static const char *state_to_str(ConversationState state);

	public:
		Conversation();
		Conversation(const FiveTuple *tuple);
		Conversation(const Packet *packet);
		~Conversation();

		/**
		 * Returns five tuple identifying the connection 
		 * (ip protocol, src ip, dst ip, src port, dst port)
		 */
		FiveTuple get_five_tuple() const;

		/**
		 * Returns const pointer to five tuple - see method get_five_tuple()
		 */
		const FiveTuple *get_five_tuple_ptr() const;

		ConversationState get_state() const;
		const char *get_state_str() const;
		virtual bool is_in_final_state() const;

		Timestamp get_start_ts() const;
		Timestamp get_last_ts() const;
		uint32_t get_duration_ms() const;
		size_t get_src_bytes() const;
		size_t get_dst_bytes() const;
		uint32_t get_packets() const;
		uint32_t get_src_packets() const;
		uint32_t get_dst_packets() const;
		uint32_t get_wrong_fragments() const;
		uint32_t get_urgent_packets() const;
		bool land() const;

		/**
		* Adds next packet to connection (without checking sequence number)
		* Returns true if connection will get to final state
		*/
		bool add_packet(const Packet *packet);

		/**
		* Output the class values (e.g. for debuging purposes)
		*/
		void print() const;

	};
}
