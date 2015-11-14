#pragma once

#include <queue>
#include <map>
#include "Conversation.h"
#include "ConversationFeatures.h"

namespace FeatureExtractor {
	template<class TStatTime, class TStatCount>
	class StatsWindow
	{
	protected:
		// TODO: create here everything templated + virtual functions for keeping the size of window 
		// Queue, methods, feature src_diff_host_rate

		// Queue of conversation in observed window
		queue<Conversation *>queue;

		// Statistics per host (destination IP)
		map<uint32_t, TStatTime> per_host;

		// Statistics per service
		TStatCount per_service[NUMBER_OF_SERVICES]

	public:
		StatsWindow();
		~StatsWindow();
		
		/**
		 * Calculates derived statistics meanwhile maintaining the queue size
		 */
		void set_derived_stats(ConversationFeatures *cf);

		/*
		 *
		 */

	};
}
