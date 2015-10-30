#include "Timestamp.h"


namespace FeatureExtractor {
	Timestamp::Timestamp()
	{
		ts.tv_sec = 0;
		ts.tv_usec = 0;
	}
	
	Timestamp::Timestamp(const struct timeval &ts)
	{
		this->ts = ts;
	}
	Timestamp::Timestamp(int64_t usecs)
	{
		ts.tv_sec = usecs / 1000000;
		ts.tv_usec = usecs % 1000000;
	}

	Timestamp::~Timestamp()
	{
	}


	struct timeval Timestamp::get_timeval() const
	{
		return ts;
	}

	int64_t Timestamp::get_usecs() const
	{
		return ts.tv_usec;
	}


	int64_t Timestamp::get_secs() const
	{
		return ts.tv_sec;
	}

	int64_t Timestamp::get_total_usecs() const
	{
		return ts.tv_sec * 1000000 + ts.tv_usec;
	}


	int64_t Timestamp::get_total_msecs() const
	{
		return (ts.tv_sec * 1000) + (ts.tv_usec / 1000);
	}


	bool Timestamp::operator==(const Timestamp &b) const
	{
		return (ts.tv_sec == b.ts.tv_sec && ts.tv_usec == b.ts.tv_usec);
	}

	Timestamp Timestamp::operator-(const Timestamp &b) const
	{
		return Timestamp(this->get_total_usecs() - b.get_total_usecs());
	}
}
