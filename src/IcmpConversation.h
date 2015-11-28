#pragma once
#include "Conversation.h"
#include "net.h"

namespace FeatureExtractor {

	/**
	 * ICMP conversation
	 * Overrides default state transition behaviour in these points:
	 *  - service name is specific for TCP and dependent on code and type fields in ICMP header
	 */
	class IcmpConversation : public Conversation
	{
		icmp_field_type_t icmp_type;
		uint8_t icmp_code;

	public:
		IcmpConversation();
		IcmpConversation(const FiveTuple *tuple);
		IcmpConversation(const Packet *packet);
		~IcmpConversation();

		icmp_field_type_t get_icmp_type();
		void set_icmp_type(icmp_field_type_t icmp_type);
		uint8_t get_icmp_code();
		void get_icmp_code(uint8_t icmp_code);

		service_t get_service() const;
	};
}