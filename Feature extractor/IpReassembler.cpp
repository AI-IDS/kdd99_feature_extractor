#include "IpReassembler.h"


namespace FeatureExtractor {
	IpReassembler::IpReassembler() 
	{
	}

	IpReassembler::IpReassemblyBufferKey::IpReassemblyBufferKey() 
		: src(0), dst(0), protocol(PROTO_ZERO), id(0)
	{}

	IpReassembler::IpReassemblyBufferKey::IpReassemblyBufferKey(Frame *frame) {
		this->src = frame->src_ip;
		this->dst = frame->dst_ip;
		this->protocol = frame->ip_protocol;
		this->id = frame->ip_id;
	}

	bool IpReassembler::IpReassemblyBufferKey::operator<(const IpReassemblyBufferKey& other) const
	{
		return (src < other.src || dst < other.dst || id < other.id || protocol < other.protocol);
	}

	IpReassembler::~IpReassembler()
	{
	}
}
