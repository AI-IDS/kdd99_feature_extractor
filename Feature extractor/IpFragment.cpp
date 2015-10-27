#include <iostream>
#include "IPFragment.h"

namespace FeatureExtractor {
	using namespace std;

	IpFragment::IpFragment()
		: Packet()
		, ip_flag_mf(0), ip_frag_offset(0), ip_payload_length(0)
	{
	}


	IpFragment::~IpFragment()
	{

	}

	uint16_t IpFragment::get_ip_id()
	{
		return ip_id;
	}

	void IpFragment::set_ip_id(uint16_t ip_id)
	{
		this->ip_id = ip_id;
	}

	bool IpFragment::get_ip_flag_mf()
	{
		return ip_flag_mf;
	}

	void IpFragment::set_ip_flag_mf(bool ip_flag_mf)
	{
		this->ip_flag_mf = ip_flag_mf;
	}

	uint16_t IpFragment::get_ip_frag_offset()
	{
		return ip_frag_offset;
	}

	void IpFragment::set_ip_frag_offset(uint16_t ip_frag_offset)
	{
		this->ip_frag_offset = ip_frag_offset;
	}

	size_t IpFragment::get_ip_payload_length()
	{
		return ip_payload_length;
	}

	void IpFragment::set_ip_payload_length(size_t ip_payload_length)
	{
		this->ip_payload_length = ip_payload_length;
	}

	void IpFragment::print()
	{
		Packet::print();
		
		cout << "  ip.mf=" << get_ip_flag_mf()
			<< ", ip.offset=" << get_ip_frag_offset() 
			<< ", ip.id=0x" << hex << get_ip_id() << dec << endl;
	}
}