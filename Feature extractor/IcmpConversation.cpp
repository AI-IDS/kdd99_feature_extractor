#include "IcmpConversation.h"

namespace FeatureExtractor {

	IcmpConversation::IcmpConversation()
		: Conversation(), icmp_type(ECHOREPLY), icmp_code(0)
	{
	}

	IcmpConversation::IcmpConversation(const FiveTuple *tuple)
		: Conversation(tuple), icmp_type(ECHOREPLY), icmp_code(0)
	{
	}

	IcmpConversation::IcmpConversation(const Packet *packet)
		: Conversation(packet)
		, icmp_type(packet->get_icmp_type())
		, icmp_code(packet->get_icmp_code())
	{
	}


	IcmpConversation::~IcmpConversation()
	{
	}


	const char *IcmpConversation::get_service() const
	{
		switch (icmp_type)
		{
		case ECHOREPLY:
			return "ecr_i";		// Echo Reply (0)
			break;

		case DEST_UNREACH:
			if (icmp_code == 0)			// Destination network unreachable
				return "urp_i";
			else if (icmp_code == 1)	// Destination host unreachable
				return "urp_i";
			else
				return "oth_i";			// Other ICMP messages;
			break;

		case REDIRECT:
			return "red_i";		// Redirect message (5)
			break;

		case ECHO:
			return "eco_i";		// Echo Request (8)
			break;

		case TIME_EXCEEDED:		// Time Exceeded (11)
			return "tim_i";
			break;

		default:
			return "oth_i";		// Other ICMP messages;
			break;
		}

		return "oth_i";			// Other ICMP messages;
	}
}