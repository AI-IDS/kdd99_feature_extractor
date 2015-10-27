#pragma once

#include "IpReassemblyBufferHoleList.h"


namespace FeatureExtractor {
	/*
	 * Reassembly buffer used to reassemble fragments of one original IP datagram.
	 * Techniques to cope with IP fragmentation based od RFC 815.
	 */
	class IpReassemblyBuffer
	{
		IpReassemblyBufferHoleList hole_list;
		
	public:
		IpReassemblyBuffer();
		~IpReassemblyBuffer();

	};
}
