#include "StatsWindowCount.h"


namespace FeatureExtractor {
	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowCount::StatsWindowCount(FeatureUpdater *feature_updater)
		: StatsWindow(feature_updater)
		, window_size(100)	// Default size = 100 conversations
	{
	}

	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowCount::StatsWindowCount(FeatureUpdater *feature_updater, unsigned int window_size)
		: StatsWindow(feature_updater)
		, window_size(window_size)
	{
	}


	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowCount::~StatsWindowCount()
	{
	}


	//template<class TStatsPerHost, class TStatsPer>
	void StatsWindowCount::perform_window_maintenance(const Conversation *new_conv)
	{
		while (queue.size > window_size) {
			Conversation *conv = queue.back();
			queue.pop();

			// Exclude removed conversation from stats
			report_conversation_removal(conv);

			// Object commits suicide if no more references to it
			conv->deregister_reference();
		}
	}

	// TODO:
	//template class StatsWindowCount<StatsPerHost, StatsPerService>;
	//template class StatsWindowCount<StatsPerHost, StatsPerServiceWithSrcPort>;
}
