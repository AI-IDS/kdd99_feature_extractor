#include "StatsPerHost.h"


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

		// count > 0 always, dont' have to treat division by zero bellow
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

		// Feature 23
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
