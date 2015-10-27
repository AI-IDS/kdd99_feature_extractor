#include "IpDatagram.h"


namespace FeatureExtractor {
	IpDatagram::IpDatagram() 
		: Packet(), frame_count(0)
	{
		end_ts.tv_sec = 0;
		end_ts.tv_usec = 0;
	}


	IpDatagram::~IpDatagram()
	{
	}


	timeval IpDatagram::get_end_ts()
	{
		return this->end_ts;
	}
	void IpDatagram::set_end_ts(timeval end_ts)
	{
		this->end_ts = end_ts;
	}

	uint16_t IpDatagram::get_frame_count()
	{
		return frame_count;
	}

	void IpDatagram::set_frame_count(uint16_t frame_count)
	{
		this->frame_count = frame_count;
	}


	void IpDatagram::inc_frame_count()
	{
		this->frame_count++;
	}
}
