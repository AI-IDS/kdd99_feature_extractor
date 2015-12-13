#pragma once

#include "types.h"
#include "Timestamp.h"

namespace FeatureExtractor {
	/**
	 * Interval watcher that is fed by timestamps representing current time
	 * and "times out" after given interval (in ms)
	 */
	class IntervalKeeper
	{
		uint64_t interval;	// in usec
		Timestamp last_ts;
		
	public:
		IntervalKeeper();
		IntervalKeeper(uint64_t interval_ms);
		~IntervalKeeper();

		uint64_t get_interval() const;
		void set_interval(uint64_t interval_ms);

		void update_time(const Timestamp &ts);
		bool is_timedout(const Timestamp &now) const;
	};
}
