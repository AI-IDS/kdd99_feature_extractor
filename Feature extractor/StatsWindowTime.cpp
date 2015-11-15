#include "StatsWindowTime.h"


namespace FeatureExtractor {
	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowTime::StatsWindowTime(FeatureUpdater *feature_updater)
		: StatsWindow(feature_updater)
		, window_size_ms(2000)		// Default size = 2 sec.
	{
	}

	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowTime::StatsWindowTime(FeatureUpdater *feature_updater, unsigned int window_size_ms)
		: StatsWindow(feature_updater)
		, window_size_ms(window_size_ms)
	{
	}

	//template<class TStatsPerHost, class TStatsPer>
	StatsWindowTime::~StatsWindowTime()
	{
	}

	//template<class TStatsPerHost, class TStatsPer>
	void StatsWindowTime::perform_window_maintenance(const Conversation *new_conv)
	{
		Timestamp now = new_conv->get_last_ts();
		Timestamp max_delete_ts = now - (window_size_ms * 1000);	// Substract usecs

		// Delete all conversations with last timestamp <= max_delete_ts
		while (queue.back()->get_last_ts <= max_delete_ts) {
			Conversation *conv = queue.back();
			queue.pop();

			// Exclude removed conversation from stats
			report_conversation_removal(conv);

			// Object commits suicide if no more references to it
			conv->deregister_reference();
		}
	}


	// TODO:
	//template class StatsWindowTime<StatsPerHost, StatsPerService>;
	//template class StatsWindowTime<StatsPerHost, StatsPerServiceWithSrcPort>;
}
