#include "StatsWindowCount.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"
#include "FeatureUpdaterCount.h"


namespace FeatureExtractor {
	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowCount<TStatsPerHost, TStatsPerService>::StatsWindowCount()
		: StatsWindow(new FeatureUpdaterCount())
		, window_size(100)	// Default size = 100 conversations
	{
	}

	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowCount<TStatsPerHost, TStatsPerService>::StatsWindowCount(unsigned int window_size)
		: StatsWindow(new FeatureUpdaterCount())
		, window_size(window_size)
	{
	}


	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowCount<TStatsPerHost, TStatsPerService>::~StatsWindowCount()
	{
	}


	template<class TStatsPerHost, class TStatsPerService>
	void StatsWindowCount<TStatsPerHost, TStatsPerService>::perform_window_maintenance(const Conversation *new_conv)
	{
		while (queue.size() > window_size) {
			Conversation *conv = queue.back();
			queue.pop();

			// Exclude removed conversation from stats
			report_conversation_removal(conv);

			// Object commits suicide if no more references to it
			conv->deregister_reference();
		}
	}

	// Explicit template specialisation
	template class StatsWindowCount<StatsPerHost, StatsPerService>;
	template class StatsWindowCount<StatsPerHost, StatsPerServiceWithSrcPort>;
}
