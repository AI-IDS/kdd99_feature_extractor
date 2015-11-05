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


	const char *UdpConversation::get_service() const
	{
		switch (five_tuple.get_dst_port())
		{
		case 53:	// DNS
			return "domain_u";
			break;

		case 69:	// TFTP
			return "tftp_u";
			break;

		case 123:	// NTP
			return "ntp_u";
			break;

		default:
			// Defined by IANA in RFC 6335 section 6:
			// the Dynamic Ports, also known as the Private or Ephemeral Ports,
			// from 49152 - 65535 (never assigned)
			if (five_tuple.get_dst_port() >= 49152)
				return "private"; // or other?
			else
				return "other";
			break;
		}

		return "other";
	}
}
