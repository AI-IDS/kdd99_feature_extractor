#pragma once

#include <map>
#include "StatsPerService.h"

namespace FeatureExtractor {
	using namespace std;

	class StatsPerServiceWithSrcPort : public StatsPerService
	{
		// 36: Number of conversations per each source port (33 split by source port)
		map<uint16_t, uint32_t> same_src_port_counts;

	public:
		StatsPerServiceWithSrcPort();
		StatsPerServiceWithSrcPort(FeatureUpdater *feature_updater);
		~StatsPerServiceWithSrcPort();

		void report_conversation_removal(const Conversation *conv);
		void report_new_conversation(ConversationFeatures *cf);
	};
}
