#include "net.h"
namespace FeatureExtractor {
	bool ether_header_t::is_ethernet2() const
	{
		return (type_length >= MIN_ETH2);
	}

	bool ether_header_t::is_type_ipv4() const
	{
		return (type_length == IPV4);
	}

	uint8_t* ether_header_t::get_eth2_sdu() const
	{
		return (((uint8_t *) this) + ETH2_HEADER_LENGTH);
	}

	uint8_t ip_header_t::ihl() const
	{
		return (ver_ihl & 0x0F);
	}

	size_t ip_header_t::header_length() const
	{
		return ihl() * sizeof(uint32_t);
	}

	uint8_t ip_header_t::flags() const
	{
		return (flags_fo & 0x7);
	}

	bool ip_header_t::flag_eb() const
	{
		return (flags() & 0x4 != 0);
	}

	bool ip_header_t::flag_df() const
	{
		return (flags() & 0x2 != 0);
	}

	bool ip_header_t::flag_mf() const
	{
		return (flags() & 0x1 != 0);
	}

	uint16_t ip_header_t::frag_offset() const
	{
		return (flags_fo >> 3);
	}

	const char *ip_header_t::protocol_str() const
	{
		switch (protocol) {
		case ICMP:
			return "ICMP";
			break;
		case TCP:
			return "TCP";
			break;
		case UDP:
			return "UDP";
			break;
		default:
			break;
		}
		return "other";
	}

	uint8_t* ip_header_t::get_sdu() const
	{
		return (((uint8_t *) this) + header_length());
	}
}