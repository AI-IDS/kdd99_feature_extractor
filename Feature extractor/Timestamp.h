#pragma once

#include <pcap.h>

namespace FeatureExtractor {
	/**
	 * Wrapper class for timeval with aditional operations
	 */
	class Timestamp
	{
		struct timeval ts;

	public:
		Timestamp();
		Timestamp(timeval ts);
		Timestamp(int64_t usecs);
		~Timestamp();

		struct timeval get_timeval() const;
		int64_t get_usecs() const;
		int64_t get_msecs() const;
		Timestamp operator-(const Timestamp &b);
	};
}

