#pragma once

#include <map>
#include <queue>
#include "net.h"
#include "Packet.h"
#include "Conversation.h"
#include "TimeoutValues.h"
#include "IntervalKeeper.h"

namespace FeatureExtractor {
	using namespace std;

	/**
	 * Engine for identification and reconstruction of conversations from IP datagrams/packets
	 */
	class ConversationReconstructor
	{
		typedef map<FiveTuple, Conversation*> ConnectionMap;
		ConnectionMap conn_map;


		// Queue of reconstructed conversations prepared to output
		queue<Conversation *>output_queue;

		// Timeout values & timeout check interval
		TimeoutValues timeouts;
		IntervalKeeper timeout_interval;

		/**
		* Removes timed out reassembly buffers - "drops incomplete datagrams"
		*/
		void check_timeouts(const Timestamp &now);
	public:
		ConversationReconstructor();
		ConversationReconstructor(TimeoutValues &timeouts);
		~ConversationReconstructor();

		 void add_packet(const Packet *packet);


		/**
		 * Returns next reconstructed conversation from internal queue.
		 *
		 * If the queueis empty nullptr is returned.
		 * Caller must take care of deallocation of returned object.
		 */
		Conversation *get_next_conversation();
	};
}

