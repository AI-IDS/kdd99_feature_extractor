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
		: Conversation(packet), icmp_type(ECHOREPLY), icmp_code(0)
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
			return "ecr_i";		// Redirect message (5)
			break;

		case ECHO:
			return "red_i";		// Echo Request (8)
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