#pragma once

#include <stdint.h>
#include "Stats.h"
#include "FeatureUpdater.h"

namespace FeatureExtractor {
	class StatsPerService : public Stats
	{
		FeatureUpdater *feature_updater;	// Used to update features in ConversationFeatures object

		// 24: # of conversations to same service
		uint32_t srv_count;

		// 26: Number of conversations that have activated the flag
		//     S0, S1, S2 or S3 among conv. srv_in count (24)
		uint32_t srv_serror_count;

		// 28: Number of conversations that have activated the flag REJ among 
		//     conv. in srv_count (24)
		uint32_t srv_rerror_count;



		// TODO: move elsewhere
		uint32_t srv_diff_host_count;

	public:
		StatsPerService(FeatureUpdater *feature_updater);
		~StatsPerService();

		void report_conversation_removal(const Conversation *conv);
		void report_new_conversation(ConversationFeatures *cf);
	};
}
