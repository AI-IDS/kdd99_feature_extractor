#include "Timestamp.h"


namespace FeatureExtractor {
	Timestamp::Timestamp()
	{
		ts.tv_sec = 0;
		ts.tv_usec = 0;
	}
	
	Timestamp::Timestamp(timeval ts)
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
		return ts.tv_sec * 1000000 + ts.tv_sec;
	}


	int64_t Timestamp::get_msecs() const
	{
		return (ts.tv_sec * 1000) + (ts.tv_usec / 1000);
	}

	Timestamp Timestamp::operator-(const Timestamp &b)
	{
		return Timestamp(this->get_usecs() - b.get_usecs());
	}
}
