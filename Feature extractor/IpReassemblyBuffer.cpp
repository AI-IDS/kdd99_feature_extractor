#include "IpReassemblyBuffer.h"
#include <assert.h>

namespace FeatureExtractor {
	using namespace std;

	IpReassemblyBuffer::IpReassemblyBuffer()
		:datagram(nullptr), frame_count(0)
	{
		first_frag_ts.tv_sec = 0;
		first_frag_ts.tv_usec = 0;
		last_frag_ts.tv_sec = 0;
		last_frag_ts.tv_usec = 0;
	}


	IpReassemblyBuffer::~IpReassemblyBuffer()
	{
	}

	IpDatagram *IpReassemblyBuffer::add_fragment(const IpFragment *frag)
	{
		// If first fragment (by order in datagram) received for the first time, 
		// create datagram with its values
		if (!datagram && frag->get_ip_frag_offset() == 0) {
			datagram = new IpDatagram(*frag);
		}
			
		// Timestamps & fragment/frame count
		if (frame_count == 0)
			first_frag_ts = frag->get_start_ts();
		last_frag_ts = frag->get_start_ts();
		frame_count++;

		// Fill holes with new fragment
		bool is_last_frag = frag->get_ip_flag_mf();		// Flag MF = 0 only for last fragment
		hole_list.add_fragment(frag->get_ip_frag_offset(), frag->get_ip_payload_length, is_last_frag);
		
		// If no hole left IP datagram is reassembled
		if (hole_list.is_empty()) {
			assert(datagram != nullptr);

			// Update timestamps & frame count
			datagram->set_start_ts(first_frag_ts);
			datagram->set_end_ts(last_frag_ts);
			datagram->set_frame_count(frame_count);

			// TODO: do this or destroy object
			IpDatagram *ret = datagram;
			datagram = nullptr;

			return datagram;
		}

		return nullptr;
	}
}
