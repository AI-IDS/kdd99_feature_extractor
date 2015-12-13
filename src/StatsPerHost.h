#pragma once

#include "types.h"
#include "StatsCollector.h"
#include "FeatureUpdater.h"

namespace FeatureExtractor {
	/**
	 * Statistics per one host (IP address)
	 */
	class StatsPerHost : public StatsCollector
	{
		FeatureUpdater *feature_updater;	// Used to update features in ConversationFeatures object

		// 23/32: Number of conversations to same destination IP
		uint32_t count;				

		// 25/38: Number of conversations that have activated the flag
		// S0, S1, S2 or S3 among conv. in count (23/32)
		uint32_t serror_count;		

		// 27/40: Number of conversations that have activated the flag REJ among 
		// conv. in count (23/32)
		uint32_t rerror_count;		
		
		// 29/34 : Number of conversations for each service (23/32 split by service)
		// Feature 30 can be derived from this: diff_srv_rate = (1 - same_srv_rate)
		// TODO: consider using map<service_t, uint32_t> to save memory
		uint32_t same_srv_counts[NUMBER_OF_SERVICES];
		
	public:
		StatsPerHost(FeatureUpdater *feature_updater);
		~StatsPerHost();

		void report_conversation_removal(const Conversation *conv);
		void report_new_conversation(ConversationFeatures *cf);
		bool is_empty();

	};
}
