#include "IpReassemblyBuffer.h"
#include <assert.h>

namespace FeatureExtractor {
	using namespace std;

	IpReassemblyBuffer::IpReassemblyBuffer()
		: datagram(nullptr), first_frag_ts(), last_frag_ts()
		, frame_count(0), total_length(0)
	{
	}


	IpReassemblyBuffer::~IpReassemblyBuffer()
	{
		// Datagram is returned by calling method add_fragment() or& must be deallocated by caller
	}

	Timestamp IpReassemblyBuffer::get_last_fragment_ts() const
	{
		return last_frag_ts;
	}

	IpDatagram *IpReassemblyBuffer::add_fragment(const IpFragment *frag)
	{
		// If first fragment (by order in datagram) received for the first time, 
		// create datagram with its values
		if (!datagram && frag->get_ip_frag_offset() == 0) {
			datagram = new IpDatagram(*frag);
		}
			
		// Timestamps, fragment/frame count & total_length of datagram
		if (frame_count == 0)
			first_frag_ts = frag->get_start_ts();
		last_frag_ts = frag->get_start_ts();
		frame_count++;
		total_length += frag->get_length();

		// Flag MF = 0 only if last fragment
		bool is_last_frag = !frag->get_ip_flag_mf();
		size_t frag_start = frag->get_ip_frag_offset();
		size_t frag_end = frag_start + frag->get_ip_payload_length() - 1;

		// Fill holes with new fragment
		hole_list.add_fragment(frag_start, frag_end, is_last_frag);
		
		// If no hole left IP datagram is reassembled
		if (hole_list.is_empty()) {
			assert(datagram != nullptr && "IP reassebly failed: NULL datagram");

			// Update timestamps, frame count & length
			datagram->set_start_ts(first_frag_ts);
			datagram->set_end_ts(last_frag_ts);
			datagram->set_frame_count(frame_count);
			datagram->set_length(total_length);

			// Caller should take care of destroying the datagram object
			IpDatagram *ret = datagram;
			datagram = nullptr;

			return ret;
		}

		return nullptr;
	}
}
