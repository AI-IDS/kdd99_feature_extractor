#include "StatsEngine.h"


namespace FeatureExtractor {
	StatsEngine::StatsEngine(const Config *config)
		: time_window(config->get_time_window_size_ms())
		, count_window(config->get_count_window_size())
	{	
	}


	StatsEngine::~StatsEngine()
	{
	}

	ConversationFeatures *StatsEngine::calculate_features(Conversation *conv)
	{
		ConversationFeatures *cf = new ConversationFeatures(conv);

		// Set time window features & to time window
		time_window.add_conversation(cf);

		// Set count window features & to count window
		count_window.add_conversation(cf);

		return cf;
	}
}
