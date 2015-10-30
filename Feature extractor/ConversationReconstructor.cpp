#include "ConversationReconstructor.h"
#include "TcpConnection.h"

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
		Conversation *conv = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove finished connection from map
		// - if connection not found, try with swapped src & dst (opposite direction)
		ConnectionMap::iterator it = conn_map.lower_bound(key);
		if (it == conn_map.end() || (conn_map.key_comp()(key, it->first))) {

			// If not found, try with opposite direction for TCP & UDP (bidirectional)
			ip_field_protocol_t ip_proto = packet->get_ip_proto();
			if (ip_proto == TCP || ip_proto == UDP) {
				it = conn_map.lower_bound(key.get_reversed());
			}
		}

		if (it != conn_map.end() && !(conn_map.key_comp()(key, it->first)))
		{
			// Key (connection) already exists
			conv = it->second;
		}
		else {
			// The key (connection) does not exist in the map
			if (packet->get_ip_proto() == TCP)
				conv = new TcpConnection(packet);
			else
				conv = new Conversation(packet);
			it = conn_map.insert(it, ConnectionMap::value_type(key, conv));
		}

		// Pass new packet to connection
		bool is_finished = conv->add_packet(packet);

		// If connection is in final state, remove it from map & return it
		if (is_finished) {
			conn_map.erase(it);	
			return conv;
		}

		return nullptr;
	}
}