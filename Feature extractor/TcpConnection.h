#pragma once

#include "Conversation.h"

namespace FeatureExtractor {
	/**
	 * TCP Connection = specific conversation
	 * Overrides default state transition behaviour in these points:
     *  - state transition behaviour (employ all states for TCP)
	 *  - evaluates whether connection is finished depending on the state 
	 *  - service name is specific for TCP and dependent od destination port
	 */
	class TcpConnection : public Conversation
	{
		virtual void update_state(const Packet *packet);

	public:
		TcpConnection();
		TcpConnection(const FiveTuple *tuple);
		TcpConnection(const Packet *packet);
		~TcpConnection();

		bool is_in_final_state() const;
		service_t get_service() const;
	};
}

