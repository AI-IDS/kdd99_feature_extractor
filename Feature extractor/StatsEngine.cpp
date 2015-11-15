#include "StatsEngine.h"


namespace FeatureExtractor {
	StatsEngine::StatsEngine()
		: time_window()		// Default size (2 sec)
		, count_window()	// Default size (100 connections)
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
