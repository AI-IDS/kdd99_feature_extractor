#include "StatsWindow.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"


namespace FeatureExtractor {
	template<class TStatTime, class TStatCount>
	StatsWindow::StatsWindow()
	{
	}

	template<class TStatTime, class TStatCount>
	StatsWindow::~StatsWindow()
	{
	}

	template<class TStatTime, class TStatCount>
	void StatsWindow::set_derived_stats(ConversationFeatures *cf)
	{
		// TODO:
		// 1. get stats for new conv
		// 2. add new conv. to stats
		// 3. update window
	}

	// Explicit template specialisation http://stackoverflow.com/q/115703/3503528
	template class StatsWindow<StatsPerHost, StatsPerService>;
	template class StatsWindow<StatsPerHost, StatsPerServiceWithSrcPort>;
}
