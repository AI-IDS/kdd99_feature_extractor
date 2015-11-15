#include "StatsWindow.h"
#include "StatsPerHost.h"
#include "StatsPerService.h"
#include "StatsPerServiceWithSrcPort.h"
#include <assert.h>


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
		// Deallocate leftover conversations in the queue
		while (!queue.empty()) {
			Conversation *conv = queue.back();
			queue.pop();

			// Object commits suicide if no more references to it
			conv->deregister_reference();
		}

		// per_host map<> should automatically be deallocated
	}

	//template<class TStatTime, class TStatCount>
	TStatsPerHost *StatsWindow::find_or_insert_host_stats(uint32_t dst_ip)
	{
		TStatsPerHost *stats = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
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
	void StatsWindow::report_conversation_removal(const Conversation *conv)
	{
		uint32_t dst_ip = conv->get_five_tuple_ptr()->get_dst_ip();
		service_t service = conv->get_service();

		// Forward to per host stats
		map<uint32_t, TStatsPerHost>::iterator it = per_host.find(dst_ip);
		assert(it != per_host.end(), "Reporting removal of convesation not in queue: no such dst. IP record");
		it->second.report_conversation_removal(conv);

		// Forward to per service stats
		per_service[service].report_conversation_removal(conv);
	}

	//template<class TStatTime, class TStatCount>
	void StatsWindow::add_conversation(ConversationFeatures *cf)
	{
		// TODO:
		// 1. get stats for new conv  x
		// 2. add new conv. to stats  x
		// 3. update window

		Conversation *conv = cf->get_conversation();
		uint32_t dst_ip = conv->get_five_tuple_ptr()->get_dst_ip();
		service_t service = conv->get_service();

		// Per host statitics 
		TStatsPerHost *this_host = find_or_insert_host_stats(dst_ip);
		this_host->report_new_conversation(cf);

		// Per service statitics 
		per_service[service].report_new_conversation(cf);

		// Add new connection to window queue (+ register reference)
		conv->register_reference();
		queue.push(conv);

		perform_window_maintenance(conv);
	}

	// TODO:
	// Explicit template specialisation http://stackoverflow.com/q/115703/3503528
	//template class StatsWindow<StatsPerHost, StatsPerService>;
	//template class StatsWindow<StatsPerHost, StatsPerServiceWithSrcPort>;
}
