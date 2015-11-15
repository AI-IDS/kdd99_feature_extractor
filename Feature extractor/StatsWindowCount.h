#pragma once
#include "StatsWindow.h"

namespace FeatureExtractor {
	/**
	 * Statistics window defined by number of connections
	 */
	template<class TStatsPerHost, class TStatsPerService>
	class StatsWindowCount : public StatsWindow<TStatsPerHost, TStatsPerService>
	{
		unsigned int window_size;

		/**
		 * Method performing window maintenance.
		 *
		 * Keeps the size of queue <= 100. Each time new conversation is added, the
		 * oldest one is removed from windows.
		 */
		void perform_window_maintenance(const Conversation *new_conv);

	public:
		StatsWindowCount();
		StatsWindowCount(unsigned int window_size);
		~StatsWindowCount();
	};
}
