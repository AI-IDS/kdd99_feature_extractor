#pragma once

#include "StatsPerService.h"

namespace FeatureExtractor {
	class StatsPerServiceWithSrcPort : public StatsPerService
	{
	public:
		StatsPerServiceWithSrcPort();
		~StatsPerServiceWithSrcPort();
	};
}
