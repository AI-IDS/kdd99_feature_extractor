#pragma once

#include <map>
#include "net.h"
#include "Packet.h"
#include "Conversation.h"

namespace FeatureExtractor {
	using namespace std;

	class ConversationReconstructor
	{
		typedef map<FiveTuple, Conversation*> ConnectionMap;
		ConnectionMap conn_map;

	public:
		ConversationReconstructor();
		~ConversationReconstructor();

		Conversation *add_packet(const Packet *packet);
	};
}

