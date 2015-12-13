#include "StatsWindowTime.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"
#include "FeatureUpdaterTime.h"


namespace FeatureExtractor {
	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowTime<TStatsPerHost, TStatsPerService>::StatsWindowTime()
		: StatsWindow<TStatsPerHost, TStatsPerService>(new FeatureUpdaterTime())
		, window_size_ms(2000)		// Default size = 2 sec.
	{
	}

	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowTime<TStatsPerHost, TStatsPerService>::StatsWindowTime(unsigned int window_size_ms)
		: StatsWindow<TStatsPerHost, TStatsPerService>(new FeatureUpdaterTime())
		, window_size_ms(window_size_ms)
	{
	}

	template<class TStatsPerHost, class TStatsPerService>
	StatsWindowTime<TStatsPerHost, TStatsPerService>::~StatsWindowTime()
	{
	}

	template<class TStatsPerHost, class TStatsPerService>
	void StatsWindowTime<TStatsPerHost, TStatsPerService>::perform_window_maintenance(const Conversation *new_conv)
	{
		Timestamp now = new_conv->get_last_ts();
		Timestamp max_delete_ts = now - (window_size_ms * 1000);	// Substract usecs

		// Delete all conversations with last timestamp <= max_delete_ts
		while (!this->finished_convs.empty() && this->finished_convs.front()->get_last_ts() <= max_delete_ts) {
			Conversation *conv = this->finished_convs.front();
			this->finished_convs.pop();

			// Exclude removed conversation from stats
			this->report_conversation_removal(conv);

			// Object commits suicide if no more references to it
			conv->deregister_reference();
		}
	}


	// Explicit template specialisation 
	template class StatsWindowTime<StatsPerHost, StatsPerService>;
	template class StatsWindowTime<StatsPerHost, StatsPerServiceWithSrcPort>;
}
