#include "IpReassembler.h"


namespace FeatureExtractor {
	IpReassembler::IpReassembler()
	{
	}

	IpReassembler::~IpReassembler()
	{
	}

	IpReassembler::IpReassemblyBufferKey::IpReassemblyBufferKey()
		: src(0), dst(0), proto(PROTO_ZERO), id(0)
	{}

	IpReassembler::IpReassemblyBufferKey::IpReassemblyBufferKey(const IpFragment *fragment) {
		this->src = fragment->get_src_ip();
		this->dst = fragment->get_dst_ip();
		this->proto = fragment->get_ip_proto();
		this->id = fragment->get_ip_id();
	}

	bool IpReassembler::IpReassemblyBufferKey::operator<(const IpReassemblyBufferKey& other) const
	{
		return (src < other.src || dst < other.dst || id < other.id || proto < other.proto);
	}



	//todo: wrap in reassemble - leaving out reas for non-fragmented packets
	IpDatagram *IpReassembler::add_fragment(const IpFragment *fragment)
	{
		IpReassemblyBufferKey key(fragment);
		IpReassemblyBuffer *buffer = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove buffer for reassembled datagram
		BufferMap::iterator it = buffer_map.lower_bound(key);
		if (it != buffer_map.end() && !(buffer_map.key_comp()(key, it->first)))
		{
			// Key already exists
			// update lb->second if you care to
			buffer = it->second;

		}
		else {
			// The key does not exist in the map
			// Add it to the map + update iterator to point to new item

			buffer = new IpReassemblyBuffer();
			it = buffer_map.insert(it, BufferMap::value_type(key, buffer));
		}

		// Call IP reassembly algorithm
		IpDatagram *datagram = buffer->add_fragment(fragment);

		// If new IP datagram reassembled, destroy the buffer for it & return it
		if (datagram) {
			buffer_map.erase(it);
			delete buffer;
		}

		return datagram;
	}
}
