#pragma once
#include "Conversation.h"
#include "net.h"

namespace FeatureExtractor {
	class IcmpConversation :
		public Conversation
	{
		icmp_field_type_t icmp_type;
		uint8_t icmp_code;

	public:
		IcmpConversation();
		~IcmpConversation();

		icmp_field_type_t get_icmp_type();
		void set_icmp_type(icmp_field_type_t icmp_type);
		uint8_t get_icmp_code();
		void get_icmp_code(uint8_t icmp_code);

		//TODO: overriden service

	};
}