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


	service_t IcmpConversation::get_service() const
	{
		switch (icmp_type)
		{
		case ECHOREPLY:
			return SRV_ECR_I;	// Echo Reply (0)
			break;

		case DEST_UNREACH:
			if (icmp_code == 0)			// Destination network unreachable
				return SRV_URP_I;
			else if (icmp_code == 1)	// Destination host unreachable
				return SRV_URH_I;
			else
				return SRV_OTH_I;		// Other ICMP messages;
			break;

		case REDIRECT:
			return SRV_RED_I;	// Redirect message (5)
			break;

		case ECHO:
			return SRV_ECO_I;	// Echo Request (8)
			break;

		case TIME_EXCEEDED:		// Time Exceeded (11)
			return SRV_TIM_I;
			break;

		default:
			return SRV_OTH_I;	// Other ICMP messages;
			break;
		}

		return SRV_OTH_I;		// Other ICMP messages;
	}
}