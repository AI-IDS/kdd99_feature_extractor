#pragma once

#include <map>
#include "IpReassemblyBuffer.h"
#include "IpFragment.h"
#include "IntervalKeeper.h"
#include "Config.h"

namespace FeatureExtractor {
	using namespace std;

	/*
	 * IP Reassembly
	 * Techniques to cope with IP fragmentation based od RFC 815
	 */
	class IpReassembler
	{
		/**
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

		// IP Reassembly buffers
		typedef map<IpReassemblyBufferKey, IpReassemblyBuffer*> BufferMap;
		BufferMap buffer_map;

		// Timeout values & timeout check interval
		Config timeouts;
		IntervalKeeper timeout_interval;

		/**
		 * Forwards fragment of fragmented datagram to correct buffer for reassembly.
		 *
		 * If reassembly is completed, datagram is returned. Otherwise the return
		 * values is nullptr.
		 */
		IpDatagram *forward_to_buffer(IpFragment *fragment);

		/**
		 * Removes timed out reassembly buffers - "drops incomplete datagrams"
		 */
		void check_timeouts(const Timestamp &now);

	public:
		IpReassembler();
		IpReassembler(Config &timeouts);
		~IpReassembler();

		/**
		 * Pass fragment to IP reassembler. 
		 *
		 * If new datagram/packet is successfully reassembled, it is returned.
		 * Otherwise nullpter is returned.
		 * IpFragment object passed by pointer might be deleted after reassembly,
		 * thus it must not be used after this call. Caller must take care 
		 * of erasing the returned object.
		 */
		Packet *reassemble(IpFragment *fragment);
	};
}

