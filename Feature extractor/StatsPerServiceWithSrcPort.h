#pragma once

#include "StatsPerService.h"

namespace FeatureExtractor {
	class StatsPerServiceWithSrcPort : public StatsPerService
	{

		// TODO: map per src port
	public:
		StatsPerServiceWithSrcPort();
		~StatsPerServiceWithSrcPort();
	};
}
