#pragma once

#include "Packet.h"

namespace FeatureExtractor {
	class IpDatagram :
		public Packet
	{
		struct timeval end_ts;
		uint16_t frame_count;
	public:
		IpDatagram();
		IpDatagram(Packet const &packet);
		~IpDatagram();

		timeval get_end_ts() const;
		void set_end_ts(timeval &end_ts);	// override

		uint16_t get_frame_count() const;
		void set_frame_count(uint16_t frame_count);
		void inc_frame_count();

		/**
		 * Output the class values (e.g. for debuging purposes)
		 * overriden
		 */
		virtual void print() const;
	};
}
