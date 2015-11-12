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
		srv_count--;

		// SYN error
		if (conv->is_serror())
			srv_serror_count--;

		// REJ error
		if (conv->is_rerror())
			srv_rerror_count--;
	}

	void StatsPerService::report_new_conversation(ConversationFeatures *cf)
	{
		const Conversation *conv = cf->get_conversation();

		// srv_count > 0 always, dont' have to treat division by zero bellow
		srv_count++;

		// SYN error
		if (conv->is_serror())
			srv_serror_count++;

		// REJ error
		if (conv->is_rerror())
			srv_rerror_count++;

		// Feature 24
		feature_updater->set_srv_count(cf, srv_count);

		// Feature 26
		double srv_serror_rate = srv_serror_count / (double)srv_count;
		feature_updater->set_srv_serror_rate(cf, srv_serror_rate);

		// Feature 28
		double srv_rerror_rate = srv_rerror_count / (double)srv_count;
		feature_updater->set_srv_rerror_rate(cf, srv_rerror_rate);

	}
}
