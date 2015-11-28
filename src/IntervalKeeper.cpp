#include "IntervalKeeper.h"


namespace FeatureExtractor {
	IntervalKeeper::IntervalKeeper()
		:interval(0), last_ts()
	{
	}

	IntervalKeeper::IntervalKeeper(uint64_t interval_ms)
		: interval(interval_ms * 1000), last_ts()
	{
	}


	IntervalKeeper::~IntervalKeeper()
	{
	}


	uint64_t IntervalKeeper::get_interval() const
	{
		return interval / 1000;
	}

	void IntervalKeeper::set_interval(uint64_t interval_ms)
	{
		this->interval = interval_ms * 1000;
	}

	void IntervalKeeper::update_time(const Timestamp &ts)
	{
		last_ts = ts;
	}

	bool IntervalKeeper::is_timedout(const Timestamp &now) const
	{
		return (now >= last_ts + interval);
	}
}
