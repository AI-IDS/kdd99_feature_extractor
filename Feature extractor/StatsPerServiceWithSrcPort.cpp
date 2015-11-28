#include "StatsPerServiceWithSrcPort.h"
#include <assert.h>

namespace FeatureExtractor {

	StatsPerServiceWithSrcPort::StatsPerServiceWithSrcPort()
		: StatsPerService()
		, same_src_port_counts() // zero-initialize
	{
	}

	StatsPerServiceWithSrcPort::StatsPerServiceWithSrcPort(FeatureUpdater *feature_updater)
		: StatsPerService(feature_updater)
		, same_src_port_counts() // zero-initialize
	{
	}


	StatsPerServiceWithSrcPort::~StatsPerServiceWithSrcPort()
	{
	}

	void StatsPerServiceWithSrcPort::report_conversation_removal(const Conversation *conv)
	{
		StatsPerService::report_conversation_removal(conv);

		uint16_t src_port = conv->get_five_tuple_ptr()->get_src_port();
		
		// Find the conversation count for source port number & decrement
		map<uint16_t, uint32_t>::iterator it = same_src_port_counts.find(src_port);
		assert(it != same_src_port_counts.end() && "Stats: reporting removal of non-existing source port");
		it->second--;

		// Remove from list if no conversation for given src port left
		if (it->second == 0) {
			same_src_port_counts.erase(it);
		}
	}

	void StatsPerServiceWithSrcPort::report_new_conversation(ConversationFeatures *cf)
	{
		StatsPerService::report_new_conversation(cf);

		uint16_t src_port = cf->get_conversation()->get_five_tuple_ptr()->get_src_port();
		uint32_t value;


		// Find or insert conversation count
		// with single lookup http://stackoverflow.com/a/101980/3503528
		map<uint16_t, uint32_t>::iterator it = same_src_port_counts.lower_bound(src_port);
		if (it != same_src_port_counts.end() && !(same_src_port_counts.key_comp()(src_port, it->first))) {
			// Key already exists, take value, then update (exclude new conversation from stats)
			value = it->second;
			it->second++;
		}
		else {
			// The key does not exist in the map
			// Add it to the map + update iterator to point to new item
			same_src_port_counts.insert(it, map<uint16_t, uint32_t>::value_type(src_port, 1));
			value = 0;
		}

		// Feature 36
		double same_src_port_rate = value / (double)srv_count;
		feature_updater->set_dst_host_same_src_port_rate(cf, same_src_port_rate);

	}
}
