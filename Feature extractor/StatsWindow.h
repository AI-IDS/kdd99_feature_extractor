#pragma once

#include <queue>
#include "Conversation.h"

namespace FeatureExtractor {
	template<class TStatTime, class TStatCount>
	class StatsWindow
	{
		// TODO: create here everything templated + virtual functions for keeping the size of window 
		// Queue, methods, feature src_diff_host_rate

		queue<Conversation *>queue;

		// map per host<>
		// array per service<>

	public:
		StatsWindow();
		~StatsWindow();
	};
}
