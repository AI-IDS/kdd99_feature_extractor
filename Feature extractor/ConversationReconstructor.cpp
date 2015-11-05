#include "ConversationReconstructor.h"
#include "TcpConnection.h"
#include "UdpConversation.h"
#include "IcmpConversation.h"
#include <assert.h>

namespace FeatureExtractor {

	ConversationReconstructor::ConversationReconstructor()
	{
	}


	ConversationReconstructor::~ConversationReconstructor()
	{
	}

	Conversation *ConversationReconstructor::add_packet(const Packet *packet)
	{
		FiveTuple key = packet->get_five_tuple();
		Conversation *conversation = nullptr;
		ip_field_protocol_t ip_proto = key.get_ip_proto();

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove finished connection from map
		// - if connection not found, try with swapped src & dst (opposite direction)
		ConnectionMap::iterator it = conn_map.lower_bound(key);
		if (it != conn_map.end() && !(conn_map.key_comp()(key, it->first)))
		{
			// Key (connection) already exists
			conversation = it->second;
		}
		else {
			// If not found, try with opposite direction for TCP & UDP (bidirectional)
			if (ip_proto == TCP || ip_proto == UDP) {
				FiveTuple rev_key = key.get_reversed();
				ConnectionMap::iterator rev_it = conn_map.lower_bound(rev_key);
				if (rev_it != conn_map.end() && !(conn_map.key_comp()(rev_key, rev_it->first)))
				{
					// Key for opposite direction already exists
					conversation = rev_it->second;
					it = rev_it;	// Remember iterator if connection should be erased below
				}
			}
		}
			
		// The key (connection) does not exist in the map
		if (!conversation) {
			switch (ip_proto)
			{
			case TCP:
				conversation = new TcpConnection(packet);
				break;

			case UDP:
				conversation = new UdpConversation(packet);
				break;

			case ICMP:
				conversation = new IcmpConversation(packet);
				break;
			}
			assert(conversation != nullptr);
			
			it = conn_map.insert(it, ConnectionMap::value_type(key, conversation));
		}

		// Pass new packet to connection
		bool is_finished = conversation->add_packet(packet);

		// If connection is in final state, remove it from map & return it
		if (is_finished) {
			conn_map.erase(it);	
			return conversation;
		}

		return nullptr;
	}
}