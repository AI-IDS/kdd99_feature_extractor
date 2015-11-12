#pragma once

#include <stdint.h>
#include "Stats.h"

namespace FeatureExtractor {
	class StatsPerHost : public Stats
	{
		uint32_t count;
		uint32_t serror_count;
		uint32_t rerror_count;

		// TODO: move these to host-service stats
		uint32_t same_srv_count;
		/* diff_srv_count = count - same_srv_count */
		
	public:
		StatsPerHost();
		~StatsPerHost();


	};
}
