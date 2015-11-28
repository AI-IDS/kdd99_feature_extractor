#pragma once

#include "IpReassemblyBufferHoleList.h"
#include "IpFragment.h"
#include "IpDatagram.h"
#include "Timestamp.h"

namespace FeatureExtractor {
	/*
	 * Reassembly buffer used to reassemble fragments of one original IP datagram.
	 * Techniques to cope with IP fragmentation based od RFC 815.
	 */
	class IpReassemblyBuffer
	{
		// Hole descriptor list - initially one hole from 0 to "infinity"
		IpReassemblyBufferHoleList hole_list;

		IpDatagram *datagram;
		Timestamp first_frag_ts;
		Timestamp last_frag_ts;
		uint16_t frame_count;
		size_t total_length;

	public:
		IpReassemblyBuffer();
		~IpReassemblyBuffer();

		Timestamp get_last_fragment_ts() const;

		IpDatagram *add_fragment(const IpFragment *fragment);
	};
}
