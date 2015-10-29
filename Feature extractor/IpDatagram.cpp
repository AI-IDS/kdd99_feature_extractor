#include <iostream>
#include "IpDatagram.h"


namespace FeatureExtractor {
	using namespace std;

	IpDatagram::IpDatagram() 
		: Packet(), end_ts(), frame_count(0)
	{
	}

	IpDatagram::IpDatagram(Packet const &packet)
		: Packet(packet), end_ts(), frame_count(0)
	{
	}


	IpDatagram::~IpDatagram()
	{
	}


	Timestamp IpDatagram::get_end_ts() const
	{
		return this->end_ts;
	}
	void IpDatagram::set_end_ts(Timestamp &end_ts)
	{
		this->end_ts = end_ts;
	}

	uint16_t IpDatagram::get_frame_count() const
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


	void IpDatagram::print() const
	{
		Packet::print();
		if (get_eth_type() == IPV4) {
			struct tm *ltime;
			char timestr[16];
			time_t local_tv_sec;
			local_tv_sec = get_end_ts().tv_sec;
			ltime = localtime(&local_tv_sec);
			strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
			cout << "  IP datagram end ts: " << timestr << endl;

		}
	}
}
