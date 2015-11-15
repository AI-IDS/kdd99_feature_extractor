#pragma once
#include "StatsWindow.h"

namespace FeatureExtractor {
	/**
	 * Statistics for time window
	 */
	// TODO: temp template hiding
	//template<class TStatsPerHost, class TStatsPer>
	class StatsWindowTime : public StatsWindow//<TStatsPerHost, TStatsPer>
	{
		unsigned int window_size_ms;

	public:
		StatsWindowTime(FeatureUpdater *feature_updater);
		StatsWindowTime(FeatureUpdater *feature_updater, unsigned int window_size_ms);
		~StatsWindowTime();

		/**
		 * Method performing window maintenance.
		 *
		 * Keeps the size of queue <= 100. Each time new conversation is added, the
		 * oldest one is removed from windows.
		 */
		void perform_window_maintenance(const Conversation *new_conv);
	};
}
