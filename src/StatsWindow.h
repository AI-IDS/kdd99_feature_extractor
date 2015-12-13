#pragma once

#include <queue>
#include <map>
#include "Conversation.h"
#include "ConversationFeatures.h"
#include "FeatureUpdater.h"

namespace FeatureExtractor {
	using namespace std;

	/**
	 * Abstract template for mantaining connection window and calculating derived features.
	 *
	 * General idea is to keep sums of desired values for conversations currently in window.
	 * For new conversations values are added. If conversation gets out of window, its values
	 * are substracted from these sums. This prevents the need of iteration over whole queue
	 * for each conversation (while calculatig its features).
	 *
	 * Algorithm performing window maintenance (keeping it's size) must be specified
	 * in derived class.
	 */
	template<class TStatsPerHost, class TStatsPerService>
	class StatsWindow
	{
	protected:
		// TODO: create here everything templated + virtual functions for keeping the size of window 
		// Queue, methods, feature src_diff_host_rate

		// Queue of conversation in observed window
		queue<Conversation *>finished_convs;

		// Statistics per host (destination IP)
		map<uint32_t, TStatsPerHost> per_host;

		// Statistics per service
		TStatsPerService per_service[NUMBER_OF_SERVICES];

		FeatureUpdater *feature_updater;

		/**
		 * Finds stats record in map<> for given host. If there is no record for such
		 * a host, a new one is inserted into map.
		 */
		TStatsPerHost *find_or_insert_host_stats(uint32_t dst_ip);

		/**
		 * Report conversation that should be excluded from window.
		 *
		 * The aim of calling this method is to keep stat. sums updated.
		 * Derived class should use this to report conversation that falls out of window
		 */
		void report_conversation_removal(const Conversation *conv);

		/**
		 * Method performing window maintenance.
		 *
		 * Implementation of this method should remove "old" conversations from window 
		 * represented by queue. 
		 * - Each removed conversation must be reported by calling report_conversation_removal().
		 * - Conversation must be deallocated by calling deregister_reference()
		 *   on it after removing it from queue. Conversation object commits suicide 
		 *   automatically when there are no more references to it. 
		 * - This method is called after every new conversation being added to window. 
		 */
		virtual void perform_window_maintenance(const Conversation *new_conv) = 0;

	public:
		StatsWindow(FeatureUpdater *feature_updater);
		virtual ~StatsWindow();

		/**
		 * Adds conversation to window, calculates & sets derived statistics.
		 * Queue (window) size maintenance is performed after each new conversation.
		 */
		void add_conversation(ConversationFeatures *cf);
	};
}
