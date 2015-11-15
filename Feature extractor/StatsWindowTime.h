#pragma once
#include "StatsWindow.h"

namespace FeatureExtractor {
	/**
	 * Statistics for time window
	 */
	template<class TStatsPerHost, class TStatsPerService>
	class StatsWindowTime : public StatsWindow<TStatsPerHost, TStatsPerService>
	{
		unsigned int window_size_ms;

		/**
		 * Method performing window maintenance.
		 *
		 * Keeps the size of queue <= 100. Each time new conversation is added, the
		 * oldest one is removed from windows.
		 */
		void perform_window_maintenance(const Conversation *new_conv);

	public:
		StatsWindowTime();
		StatsWindowTime(unsigned int window_size_ms);
		~StatsWindowTime();
	};
}
