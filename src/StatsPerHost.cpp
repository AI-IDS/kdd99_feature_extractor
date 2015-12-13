#include "StatsPerHost.h"

// MSVC: Disable C4351 warning message:
// new behavior: elements of array 'StatsPerHost::same_srv_counts' will be default initialized
#ifdef _MSC_VER
	#pragma warning(disable:4351)
#endif

namespace FeatureExtractor {

	StatsPerHost::StatsPerHost(FeatureUpdater *feature_updater)
		: feature_updater(feature_updater)
		, count(0), serror_count(0), rerror_count()
		, same_srv_counts()	// zero-initialize
	{
	}


	StatsPerHost::~StatsPerHost()
	{
	}

	void StatsPerHost::report_conversation_removal(const Conversation *conv)
	{
		count--;

		// SYN error
		if (conv->is_serror())
			serror_count--;

		// REJ error
		if (conv->is_rerror())
			rerror_count--;

		// Number of conv. per service
		service_t service = conv->get_service();
		same_srv_counts[service]--;

	}

	void StatsPerHost::report_new_conversation(ConversationFeatures *cf)
	{
		const Conversation *conv = cf->get_conversation();
		service_t service = conv->get_service();

		/*
		 * Set derived window features based on previous conversations in window
		 */
		// Feature 23/32
		feature_updater->set_count(cf, count);

		// Feature 25/38
		double serror_rate = (count == 0) ? 0.0 : (serror_count / (double)count);
		feature_updater->set_serror_rate(cf, serror_rate);

		// Feature 27/40
		double rerror_rate = (count == 0) ? 0.0 : (rerror_count / (double)count);
		feature_updater->set_rerror_rate(cf, rerror_rate);

		// Feature 29/34
		double same_srv_rate = (count == 0) ? 0.0 : (same_srv_counts[service] / (double)count);
		feature_updater->set_same_srv_rate(cf, same_srv_rate);

		// Feature 30
		double diff_srv_rate = (count == 0) ? 0.0 : (1.0 - same_srv_rate);
		feature_updater->set_diff_srv_rate(cf, diff_srv_rate);

		// Part of feature 31/37
		feature_updater->set_same_srv_count(cf, same_srv_counts[service]);

		/*
		 * Include new conversation to stats
		 */
		count++;	

		// SYN error
		if (conv->is_serror())
			serror_count++;

		// REJ error
		if (conv->is_rerror())
			rerror_count++;

		// Number of conv. per service
		same_srv_counts[service]++;
	}

	bool StatsPerHost::is_empty()
	{
		return (count == 0);
	}

}
