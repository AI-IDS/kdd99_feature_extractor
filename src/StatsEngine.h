#pragma once

#include "StatsWindowTime.h"
#include "StatsWindowCount.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"
#include "Config.h"

namespace FeatureExtractor {
	/**
	 * Statistical engine for computation of derived features
	 */
	class StatsEngine
	{
		StatsWindowTime<StatsPerHost, StatsPerService> time_window;
		StatsWindowCount<StatsPerHost, StatsPerServiceWithSrcPort> count_window;

	public:
		StatsEngine(const Config *config);
		~StatsEngine();

		/**
		 * Passes new conversation to statistical engine. Features for given 
		 * conversation are returned.
		 *
		 * Caller is responsible for deallocation of returned instance. Original
		 * Conversation object should not be used after returned instance of class
		 * ConversationFeatures was deallocated.
		 */
		ConversationFeatures *calculate_features(Conversation *conv);
	};
}
