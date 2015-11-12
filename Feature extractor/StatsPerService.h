#pragma once

#include <stdint.h>
#include "Stats.h"

namespace FeatureExtractor {
	class StatsPerService : public Stats
	{
		uint32_t srv_count;
		uint32_t srv_serror_count;
		uint32_t srv_rerror_count;
		uint32_t srv_diff_host_count;

	public:
		StatsPerService();
		~StatsPerService();
	};
}
