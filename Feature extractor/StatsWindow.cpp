#include "StatsWindow.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"


namespace FeatureExtractor {
	//template<class TStatTime, class TStatCount>
	StatsWindow::StatsWindow(FeatureUpdater *feature_updater)
		: feature_updater(feature_updater)
	{
		// Initialize stats per service
		for (int i = 0; i < NUMBER_OF_SERVICES; i++) {
			per_service[i] = TStatsPerService(feature_updater);
		}
	}

	//template<class TStatTime, class TStatCount>
	StatsWindow::~StatsWindow()
	{
	}

	//template<class TStatTime, class TStatCount>
	TStatsPerHost *StatsWindow::find_or_insert_host_stats(uint32_t dst_ip)
	{
		TStatsPerHost *stats = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove buffer for reassembled datagram
		map<uint32_t, TStatsPerHost>::iterator it = per_host.lower_bound(dst_ip);
		if (it != per_host.end() && !(per_host.key_comp()(dst_ip, it->first)))
		{
			// Found
			stats = &it->second;
		}
		else {
			// The key does not exist in the map
			// Add it to the map + update iterator to point to new item
			it = per_host.insert(it, map<uint32_t, TStatsPerHost>::value_type(dst_ip, TStatsPerHost(feature_updater)));
			stats = &it->second;
		}

		return stats;
	}

	//template<class TStatTime, class TStatCount>
	void StatsWindow::add_conversation(ConversationFeatures *cf)
	{
		// TODO:
		// 1. get stats for new conv  x
		// 2. add new conv. to stats  x
		// 3. update window

		const Conversation *conv = cf->get_conversation();
		uint32_t dst_ip = conv->get_five_tuple_ptr()->get_dst_ip();
		service_t service = conv->get_service();

		// Per host statitics 
		TStatsPerHost *this_host = find_or_insert_host_stats(dst_ip);
		this_host->report_new_conversation(cf);

		// Per service statitics 
		per_service[service].report_new_conversation(cf);

		// Add new connection to window queue
		queue.push(conv);

		perform_window_maintenance(conv);
	}

	// TODO:
	// Explicit template specialisation http://stackoverflow.com/q/115703/3503528
	//template class StatsWindow<StatsPerHost, StatsPerService>;
	//template class StatsWindow<StatsPerHost, StatsPerServiceWithSrcPort>;
}
