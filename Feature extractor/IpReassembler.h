#pragma once

#include <map>
#include "IpReassemblyBuffer.h"
#include "Frame.h"

namespace FeatureExtractor {
	using namespace std;

	/*
	 * IP Reassembly
	 * Techniques to cope with IP fragmentation based od RFC 815
	 */
	class IpReassembler
	{
		/*
		 * Reassembly buffer identification (key for map)
		 * RFC 815 Section 7:
		 * The correct reassembly buffer is identified by an equality of the following 
		 * fields:  the  foreign  and  local  internet  address,  the protocol ID, 
		 * and the identification field.
		 */
		class IpReassemblyBufferKey {
			uint32_t src;
			uint32_t dst;
			ip_field_protocol_t proto;
			uint16_t id;
		public:
			IpReassemblyBufferKey();
			IpReassemblyBufferKey(const IpFragment *fragment);
			bool operator<(const IpReassemblyBufferKey& other) const; // Required for map<> key
		};

		typedef map<IpReassemblyBufferKey, IpReassemblyBuffer*> BufferMap;
		BufferMap buffer_map;


	public:
		IpReassembler();
		~IpReassembler();


		IpDatagram *add_fragment(const IpFragment *fragment);

	};
}

