#pragma once

#include <map>
#include <queue>
#include "net.h"
#include "Packet.h"
#include "Conversation.h"
#include "Config.h"
#include "IntervalKeeper.h"

namespace FeatureExtractor {
	using namespace std;

	/**
	 * Engine for identification and reconstruction of conversations from IP datagrams/packets
	 */
	class ConversationReconstructor
	{
		typedef map<FiveTuple, Conversation*> ConversationMap;
		ConversationMap conv_map;


		// Queue of reconstructed conversations prepared to output
		queue<Conversation *>output_queue;

		// Timeout values & timeout check interval
		Config timeouts;
		IntervalKeeper timeout_interval;

		/**
		 * Removes timed out reassembly buffers - "drops incomplete datagrams"
		 */
		void check_timeouts(const Timestamp &now);
	public:
		ConversationReconstructor();
		ConversationReconstructor(Config &timeouts);
		~ConversationReconstructor();

		/**
		 * Send next packet to conversation reconstruction engine
		 */
		 void add_packet(const Packet *packet);

		 /**
		  * When no new packets, time can be reported to timeout old connections
		  */
		 void report_time(const Timestamp &now);

		/**
		 * Returns next reconstructed conversation from internal queue of finished conversation.
		 *
		 * Conversations are returned in order the ended (sorted by the timestamp 
		 * of their last packet).
		 * If the queueis empty nullptr is returned.
		 * Caller must take care of deallocation of returned object.
		 */
		Conversation *get_next_conversation();

		/**
		 * Places timeout on all active conversations
		 * Can be used to get unfinished conversations when no more traffic available
		 */
		void finish_all_conversations();
	};
}

