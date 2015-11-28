#include "UdpConversation.h"

namespace FeatureExtractor {

	UdpConversation::UdpConversation()
	{
	}

	UdpConversation::UdpConversation(const FiveTuple *tuple)
		: Conversation(tuple)
	{
	}

	UdpConversation::UdpConversation(const Packet *packet)
		: Conversation(packet)
	{
	}


	UdpConversation::~UdpConversation()
	{
	}


	service_t UdpConversation::get_service() const
	{
		switch (five_tuple.get_dst_port())
		{
		case 53:	// DNS
			return SRV_DOMAIN_U;
			break;

		case 69:	// TFTP
			return SRV_TFTP_U;
			break;

		case 123:	// NTP
			return SRV_NTP_U;
			break;

		default:
			// Defined by IANA in RFC 6335 section 6:
			// the Dynamic Ports, also known as the Private or Ephemeral Ports,
			// from 49152 - 65535 (never assigned)
			if (five_tuple.get_dst_port() >= 49152)
				return SRV_PRIVATE;
			else
				return SRV_OTHER;
			break;
		}

		return SRV_OTHER;
	}
}
