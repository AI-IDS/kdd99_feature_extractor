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

	void ConversationReconstructor::add_packet(const Packet *packet)
	{
		// TODO: check timeouts here

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

		// If connection is in final state, remove it from map & enqueue to output
		if (is_finished) {
			conn_map.erase(it);	
			output_queue.push(conversation);
		}
	}

	Conversation *ConversationReconstructor::get_next_conversation()
	{
		if (output_queue.empty())
			return nullptr;

		Conversation *conv = output_queue.front();
		output_queue.pop();
		return conv;
	}


	void ConversationReconstructor::check_timeouts(const Timestamp &now)
	{
		// find, sort, add to queue

		// Maximal timestamp that timedout connection can have
		Timestamp max_timeout_ts = now - (ipfrag_time * 1000000);

		// Erasing during iteration available since C++11
		// http://stackoverflow.com/a/263958/3503528
		ConnectionMap::iterator it = conn_map.begin();
		while (it != conn_map.end()) {

			//// If buffer is timed out, DROP the incomplete datagram
			//if (it->second->get_last_fragment_ts() <= max_timeout_ts) {
			//	// Erase
			//	buffer_map.erase(it++);  // Use iterator + post increment
			//}
			//else {
			//	++it;
			//}
		} // end of while(it..

	}
}