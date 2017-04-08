#include "ConversationReconstructor.h"
#include "types.h"
#include "TcpConnection.h"
#include "UdpConversation.h"
#include "IcmpConversation.h"
#include <assert.h>
#include <algorithm>


namespace FeatureExtractor {
	using namespace std;

	ConversationReconstructor::ConversationReconstructor()
		: timeouts()
		, timeout_interval(timeouts.get_conversation_check_interval_ms())
	{
	}

	ConversationReconstructor::ConversationReconstructor(Config &timeouts)
		: timeouts(timeouts)
		, timeout_interval(timeouts.get_conversation_check_interval_ms())
	{
	}

	ConversationReconstructor::~ConversationReconstructor()
	{
		// Deallocate leftover conversations in output queue
		while (!output_queue.empty()) {
			delete output_queue.front();
			output_queue.pop();
		}

		// Deallocate leftover active conversations
		for (ConversationMap::iterator it = conv_map.begin(); it != conv_map.end(); ++it) {
			delete it->second;
		}
	}

	void ConversationReconstructor::add_packet(const Packet *packet)
	{
		// Remove timed out reassembly conversations
		Timestamp now = packet->get_end_ts();
		check_timeouts(now);

		FiveTuple key = packet->get_five_tuple();
		Conversation *conversation = nullptr;
		ip_field_protocol_t ip_proto = key.get_ip_proto();

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove finished connection from map
		// - if connection not found, try with swapped src & dst (opposite direction)
		ConversationMap::iterator it = conv_map.lower_bound(key);
		if (it != conv_map.end() && !(conv_map.key_comp()(key, it->first)))
		{
			// Key (connection) already exists
			conversation = it->second;
		}
		else {
			// If not found, try with opposite direction for TCP & UDP (bidirectional)
			if (ip_proto == TCP || ip_proto == UDP) {
				FiveTuple rev_key = key.get_reversed();
				ConversationMap::iterator rev_it = conv_map.lower_bound(rev_key);
				if (rev_it != conv_map.end() && !(conv_map.key_comp()(rev_key, rev_it->first)))
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

			default:
				break;
			}
			assert(conversation != nullptr && "Attempt to add NULL "
				"conversation to conversation map. Possible unhadnled IP protocol value");
			
			it = conv_map.insert(it, ConversationMap::value_type(key, conversation));
		}

		// Pass new packet to conversation
		bool is_finished = conversation->add_packet(packet);

		// If connection is in final state, remove it from map & enqueue to output
		if (is_finished) {
			conv_map.erase(it);
			output_queue.push(conversation);
		}
	}


	void ConversationReconstructor::report_time(const Timestamp &now)
	{
		check_timeouts(now);
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
		// Run no more often than once per timeout check interval
		if (!timeout_interval.is_timedout(now)) {
			timeout_interval.update_time(now);
			return;
		}
		timeout_interval.update_time(now);

		// Maximal timestamp that timedout connection can have
		Timestamp max_tcp_syn = now - (timeouts.get_tcp_syn_timeout() * 1000000);
		Timestamp max_tcp_estab = now - (timeouts.get_tcp_estab_timeout() * 1000000);
		Timestamp max_tcp_rst = now - (timeouts.get_tcp_rst_timeout() * 1000000);
		Timestamp max_tcp_fin = now - (timeouts.get_tcp_fin_timeout() * 1000000);
		Timestamp max_tcp_last_ack = now - (timeouts.get_tcp_last_ack_timeout() * 1000000);
		Timestamp max_udp = now - (timeouts.get_udp_timeout() * 1000000);
		Timestamp max_icmp = now - (timeouts.get_icmp_timeout() * 1000000);

		// Temporary list of timed out conversations
		vector<Conversation *> timedout_convs;

		// Erasing during iteration available since C++11
		// http://stackoverflow.com/a/263958/3503528
		ConversationMap::iterator it = conv_map.begin();
		while (it != conv_map.end()) {
			bool is_timedout = false;
			Conversation *conv = it->second;
			ip_field_protocol_t ip_proto = conv->get_five_tuple_ptr()->get_ip_proto();

			// Check if conversation is timedout
			if (ip_proto == UDP) {
				is_timedout = (conv->get_last_ts() <= max_udp);
			}
			else if (ip_proto == ICMP) {
				is_timedout = (conv->get_last_ts() <= max_icmp);
			}
			else if (ip_proto == TCP) {
				switch (conv->get_internal_state()) {
				case S0:
				case S1:
					is_timedout = (conv->get_last_ts() <= max_tcp_syn);
					break;

				case ESTAB:
					is_timedout = (conv->get_last_ts() <= max_tcp_estab);
					break;

				case REJ:
				case RSTO:
				case RSTOS0:
				case RSTR:
					is_timedout = (conv->get_last_ts() <= max_tcp_rst);
					break;

				case S2:
				case S3:
					is_timedout = (conv->get_last_ts() <= max_tcp_fin);
					break;

				case S2F:
				case S3F:
					is_timedout = (conv->get_last_ts() <= max_tcp_last_ack);
					break;

				default:
					break;
				}
			}

			// If buffer is timed out, remove conversation from active conversations
			// and to temporary list of timed out conversations
			if (is_timedout) {
				timedout_convs.push_back(conv);
				conv_map.erase(it++);
			}
			else {
				++it;
			}
		} // end of while(it..

		// Sort timed out conversations by timestamp of last fragmet seen
		// Overriden operator '<' of class Conversation is used
		sort(timedout_convs.begin(), timedout_convs.end());

		// Add timedout conversation to output queue in order of their last timestamp
		for (vector<Conversation *>::iterator it = timedout_convs.begin(); it != timedout_convs.end(); ++it) {
			output_queue.push(*it);
		}
	}

	void ConversationReconstructor::finish_all_conversations()
	{
		// Temporary list of timed out conversations
		vector<Conversation *> timedout_convs;

		// Erasing during iteration available since C++11
		// http://stackoverflow.com/a/263958/3503528
		ConversationMap::iterator it = conv_map.begin();
		while (it != conv_map.end()) {
			Conversation *conv = it->second;
			timedout_convs.push_back(conv);
			conv_map.erase(it++);
		}

		// Sort timed out conversations by timestamp of last fragmet seen
		// Overriden operator '<' of class Conversation is used
		sort(timedout_convs.begin(), timedout_convs.end());

		// Add timeout conversation to output queue in order of their last timestamp
		for (vector<Conversation *>::iterator it = timedout_convs.begin(); it != timedout_convs.end(); ++it) {
			output_queue.push(*it);
		}
	}
}
