#pragma once

#include <queue>
#include <map>
#include "Conversation.h"
#include "ConversationFeatures.h"

// TODO: temp includes 
#include "StatsPerHost.h"
#include "StatsPerService.h"


namespace FeatureExtractor {
	/**
	 * Abstract template for mantaining connection window and calculating derived features
	 *
	 * Algorithm performing window maintenance (keeping it's size) must be specified
	 * in derived class.
	 */
	

	// TODO: temp typedefs
	typedef StatsPerHost TStatsPerHost;
	typedef StatsPerService TStatsPerService;

	//template<class TStatsPerHost, class TStatsPer>
	class StatsWindow
	{
	protected:
		// TODO: create here everything templated + virtual functions for keeping the size of window 
		// Queue, methods, feature src_diff_host_rate

		// Queue of conversation in observed window
		queue<const Conversation *>queue;

		// Statistics per host (destination IP)
		map<uint32_t, TStatsPerHost> per_host;

		// Statistics per service
		StatsPerService per_service[NUMBER_OF_SERVICES];

		FeatureUpdater *feature_updater;

		StatsPerHost *find_or_insert_host_stats(uint32_t dst_ip);

		/**
		 * Method performing window maintenance.
		 *
		 * Implementation of this method should remove "old" conversations from window 
		 * represented by queue. Conversation must be deallocated by calling deregister_reference()
		 * on it after removing it (Conversation object commits suicide when there are no more 
		 * references to it. 
		 * This method is called after every new conversation being added to window. 
		 //TODO: remove reference 
		 */
		virtual void perform_window_maintenance(const Conversation *new_conv) = 0;

	public:
		StatsWindow(FeatureUpdater *feature_updater);
		~StatsWindow();

		/**
		 * Adds conversation to window and calculates derived statistics
		 * Queue (window) size maintenance is performed after each new conversation.
		 */
		void add_conversation(ConversationFeatures *cf);

		/*
		 *
		 */

	};
}
