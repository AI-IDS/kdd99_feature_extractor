#pragma once
#include "Conversation.h"

namespace FeatureExtractor {

	/**
	 * UDP conversation
	 * Overrides default state transition behaviour in these points:
	 *  - service name is specific for TCP and dependent od destination port
	 */
	class UdpConversation : public Conversation
	{
	public:
		UdpConversation();
		UdpConversation(const FiveTuple *tuple);
		UdpConversation(const Packet *packet);
		~UdpConversation();

		service_t get_service() const;
	};

}
