#pragma once
#include "StatsWindow.h"

namespace FeatureExtractor {
	/**
	 * Statistics window defined by number of connections
	 */
	// TODO: temp template hiding
	//template<class TStatsPerHost, class TStatsPer>
	class StatsWindowCount : public StatsWindow//<TStatsPerHost, TStatsPer>
	{
		unsigned int window_size;

	public:
		StatsWindowCount(FeatureUpdater *feature_updater);
		StatsWindowCount(FeatureUpdater *feature_updater, unsigned int window_size);
		~StatsWindowCount();

		/**
		* Method performing window maintenance.
		*
		* Keeps the size of queue <= 100. Each time new conversation is added, the 
		* oldest one is removed from windows.
		*/
		void perform_window_maintenance(const Conversation *new_conv);
	};
}
