#include "StatsPerService.h"


namespace FeatureExtractor {
	StatsPerService::StatsPerService(FeatureUpdater *feature_updater)
		: feature_updater(feature_updater)
		, srv_count(0), srv_serror_count(0), srv_rerror_count(0)
	{
	}


	StatsPerService::~StatsPerService()
	{
	}

	void StatsPerService::report_conversation_removal(const Conversation *conv)
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

	void StatsPerService::report_new_conversation(ConversationFeatures *cf)
	{
		const Conversation *conv = cf->get_conversation();
		count++;

		// SYN error
		if (conv->is_serror())
			serror_count++;

		// REJ error
		if (conv->is_rerror())
			rerror_count++;

		// Number of conv. per service
		service_t service = conv->get_service();
		same_srv_counts[service]++;

		// Set feature 23
		feature_updater->set_count(cf, count);

		// Feature 25
		double serror_rate = serror_count / (double)count;
		feature_updater->set_serror_rate(cf, serror_rate);

		// Feature 25
		double rerror_rate = rerror_count / (double)count;
		feature_updater->set_rerror_rate(cf, rerror_rate);

		// Feature 29
		double same_srv_rate = same_srv_counts[service] / (double)count;
		feature_updater->set_same_srv_rate(cf, same_srv_rate);

		// Feature 30
		feature_updater->set_diff_srv_rate(cf, 1.0 - same_srv_rate);
	}
}
