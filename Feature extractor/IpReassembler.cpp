#include "IpReassembler.h"


namespace FeatureExtractor {
	// 
	
	IpReassembler::IpReassembler()
		: ipfrag_time(30)				// IP Fragmentation timeout 30s (Linux default)
										// http://www.linuxinsight.com/proc_sys_net_ipv4_ipfrag_time.html
		, timeout_interval(1 * 1000000)	// Check for timeouts every second
	{
	}

	IpReassembler::IpReassembler(uint32_t ipfrag_time, uint64_t timeout_check_interval)
		: ipfrag_time(ipfrag_time)
		, timeout_interval(timeout_check_interval)
	{
	}


	IpReassembler::~IpReassembler()
	{
		// TODO: release buffer_map, output_queue

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

		if (src < other.src)
			return true;
		if (src > other.src)
			return false;

		// src IPs are equal
		if (dst < other.dst)
			return true;
		if (dst > other.dst)
			return false;

		// dst IPs are equal
		if (id < other.id)
			return true;
		if (id > other.id)
			return false;

		// IDs are equal
		return (proto < other.proto);
	}


	Packet *IpReassembler::pass_new_fragment(IpFragment *frag)
	{
		// Removes timed out reassembly buffers once per interval
		Timestamp now = frag->get_end_ts();
		if (timeout_interval.is_timedout(now))
			check_timeouts(now);
		timeout_interval.update_time(now);

		// Check whether packet is part of fragmented datagram
		bool is_fragmented = (frag->get_ip_flag_mf() || frag->get_ip_frag_offset() != 0);

		// If fragmented forward to correct reassembly buffer
		if (is_fragmented)
			return forward_to_buffer(frag);
		
		// Not fragmented, nothing to do 
		return frag;
	}

	IpDatagram *IpReassembler::forward_to_buffer(IpFragment *frag)
	{
		IpReassemblyBufferKey key(frag);
		IpReassemblyBuffer *buffer = nullptr;

		// Find or insert with single lookup: 
		// http://stackoverflow.com/a/101980/3503528
		// - iterator can will also used to remove buffer for reassembled datagram
		BufferMap::iterator it = buffer_map.lower_bound(key);
		if (it != buffer_map.end() && !(buffer_map.key_comp()(key, it->first)))
		{
			// Key already exists; update lb->second if you care to
			buffer = it->second;
		}
		else {
			// The key does not exist in the map
			// Add it to the map + update iterator to point to new item
			buffer = new IpReassemblyBuffer();
			it = buffer_map.insert(it, BufferMap::value_type(key, buffer));
		}

		// Call IP reassembly algorithm
		IpDatagram *datagram = buffer->add_fragment(frag);

		// If new IP datagram reassembled, destroy the buffer for it
		// and enqueue datagram to output queue
		if (datagram) {
			buffer_map.erase(it);
			delete buffer;
		}

		// Free fragment from memory
		delete frag;

		return datagram;
	}

	void IpReassembler::check_timeouts(const Timestamp &now)
	{
		// find, sort, add to queue

		// Maximal timestamp that timedout buffer can have
		Timestamp max_timeout_ts = now - (ipfrag_time * 1000000);

		// Erasing during iteration available since C++11
		// http://stackoverflow.com/a/263958/3503528
		BufferMap::iterator it = buffer_map.begin();
		while (it != buffer_map.end()) {

			// If buffer is timed out, DROP the incomplete datagram
			if (it->second->get_last_fragment_ts() <= max_timeout_ts) {
				// Erase
				buffer_map.erase(it++);  // Use iterator + post increment
			}
			else {
				++it;
			}
		} // end of while(it..

	}

}
